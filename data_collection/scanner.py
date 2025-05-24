"""
信息收集主协调器
负责协调各个扫描模块，管理缓存和配置，处理代理数据并分发扫描任务
"""
import asyncio
import contextlib
import traceback
from urllib.parse import urlparse
from django.utils import timezone
from asgiref.sync import sync_to_async

from .models import Asset, ScanResult, SystemSettings, SkipTarget
from .modules.network_scanner import NetworkScanner
from .modules.os_scanner import OSScanner
from .modules.component_scanner import ComponentScanner
from .modules.scan_helpers import ScanHelpers


class DataCollectionScanner:
    """
    数据采集扫描器：负责协调各个扫描模块进行扫描
    """

    def __init__(self):
        """初始化扫描器"""
        self.is_scanning = False
        self.use_proxy = False
        self.proxy_address = "http://localhost:7890"
        self.scan_timeout = 10  # 默认扫描超时时间（秒）
        self.max_concurrent_scans = 5  # 默认最大并发扫描数
        self.skip_targets = set()  # 要跳过的目标集合
        self.semaphore = asyncio.Semaphore(5)  # 默认并发数控制
        self.scan_lock = asyncio.Lock()  # 全局扫描锁

        # 初始化各个扫描模块
        self.network_scanner = NetworkScanner()
        self.os_scanner = OSScanner()
        self.component_scanner = ComponentScanner()
        self.helpers = ScanHelpers()

        # 添加全局级别的结果缓存，防止同一次扫描中产生重复结果
        # 格式: (asset_id, module, description, rule_type, match_value_hash)
        self.global_result_cache = set()

        # 添加已扫描资产跟踪
        self.scanned_assets = set()  # 记录已扫描资产ID

        # 添加结果缓存跟踪
        self.result_cache = set()  # 记录已发送的结果ID

        # 添加进行中的扫描任务跟踪
        # 格式: {url: Future}
        self.pending_scans = {}

        # 添加状态标志
        self.cancel_requested = False

    # 增强的重置扫描状态方法
    def reset_scan_state(self, clear_global_cache=True):
        """重置扫描状态，清除缓存"""
        self.scanned_assets.clear()  # 清除资产记录
        self.result_cache.clear()  # 清除结果缓存
        self.pending_scans.clear()  # 清除进行中的扫描任务
        self.cancel_requested = False  # 重置取消标志

        if clear_global_cache:
            self.global_result_cache.clear()  # 清除全局结果缓存
            print("全局结果缓存已清除")

        # 重置各个扫描模块的缓存
        if hasattr(self.network_scanner, 'clear_cache'):
            self.network_scanner.clear_cache()
            print("网络扫描模块缓存已清除")

        if hasattr(self.os_scanner, 'clear_cache'):
            self.os_scanner.clear_cache()
            print("操作系统扫描模块缓存已清除")

        if hasattr(self.component_scanner, 'clear_cache'):
            self.component_scanner.clear_cache()
            print("组件扫描模块缓存已清除")

        print("扫描状态已重置")

    # 检查结果是否已存在于全局缓存中，增加match_value参数
    def is_result_in_cache(self, asset_id, module, description, rule_type, match_value=""):
        """
        检查结果是否已存在于全局缓存中

        参数:
            asset_id: 资产ID
            module: 模块名称 (network, os, component)
            description: 规则描述
            rule_type: 规则类型
            match_value: 匹配值(可选)

        返回:
            是否存在于缓存中
        """
        # 基本缓存键
        basic_cache_key = (asset_id, module, description, rule_type)

        # 首先检查基本键
        if basic_cache_key in self.global_result_cache:
            return True

        # 如果提供了match_value，生成详细缓存键
        if match_value:
            # 对较长的match_value使用哈希值，避免存储过长的字符串
            match_value_hash = hash(match_value) if len(match_value) > 100 else match_value
            detailed_cache_key = basic_cache_key + (match_value_hash,)
            return detailed_cache_key in self.global_result_cache

        return False

    # 添加结果到全局缓存，增加match_value参数
    def add_result_to_cache(self, asset_id, module, description, rule_type, match_value=""):
        """将结果添加到全局缓存"""
        # 基本缓存键
        basic_cache_key = (asset_id, module, description, rule_type)

        # 添加基本键到全局缓存
        self.global_result_cache.add(basic_cache_key)

        # 如果提供了match_value，添加详细缓存键
        if match_value:
            # 对较长的match_value使用哈希值
            match_value_hash = hash(match_value) if len(match_value) > 100 else match_value
            detailed_cache_key = basic_cache_key + (match_value_hash,)
            self.global_result_cache.add(detailed_cache_key)

        print(f"结果已添加到全局缓存: {basic_cache_key}")

    # 请求取消所有扫描任务
    def request_cancel(self):
        """请求取消所有扫描任务"""
        self.cancel_requested = True
        print("已请求取消所有扫描任务")

    async def scan_data(self, channel_layer, asset_id, url, method, status_code, req_headers, req_content, resp_headers,
                        resp_content):
        """
        扫描数据（主入口）

        参数:
            channel_layer: 通道层
            asset_id: 资产ID
            url: URL
            method: HTTP方法
            status_code: 响应状态码
            req_headers: 请求头
            req_content: 请求内容
            resp_headers: 响应头
            resp_content: 响应内容
        """
        # 先发送通知表示扫描开始
        await channel_layer.group_send(
            'data_collection_scanner',
            {
                'type': 'scan_progress',
                'data': {
                    'status': 'scanning',
                    'message': f'开始扫描: {url}',
                    'url': url,
                    'progress': 0
                }
            }
        )

        # 创建非阻塞任务执行实际扫描
        task = asyncio.create_task(
            self._do_scan(
                channel_layer, asset_id, url, method, status_code,
                req_headers, req_content, resp_headers, resp_content
            )
        )

        # 记录任务以便于后续管理
        self.pending_scans[url] = task

        # 不等待任务完成，立即返回
        return

    async def _do_scan(self, channel_layer, asset_id, url, method, status_code,
                     req_headers, req_content, resp_headers, resp_content):
        """实际执行扫描的内部方法"""
        # 添加调试信息
        print(f"开始扫描资产{asset_id}: {url}, 方法: {method}, 状态码: {status_code}")

        # 解析URL获取主机名
        parsed_url = urlparse(url)
        host = parsed_url.netloc

        # 检查是否需要跳过此目标
        if host in self.skip_targets:
            print(f"跳过目标: {host} (在跳过列表中)")
            return

        # 检查是否已请求取消
        if self.cancel_requested:
            print(f"已请求取消扫描，跳过: {url}")
            return

        # 尝试使用信号量控制并发，但加入超时以避免永久阻塞
        try:
            # 获取信号量的尝试，最多等待5秒
            acquire_task = asyncio.create_task(self.semaphore.acquire())
            done, pending = await asyncio.wait([acquire_task], timeout=5)

            if acquire_task not in done:
                # 超时未获取到信号量
                acquire_task.cancel()
                print(f"获取扫描信号量超时，跳过: {url}")

                # 发送通知
                await channel_layer.group_send(
                    'data_collection_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'error',
                            'message': '扫描队列已满，请稍后再试',
                            'url': url,
                            'progress': 0
                        }
                    }
                )
                return

            # 设置信号量大小（可能在运行时被修改）
            self.semaphore._value = self.max_concurrent_scans
        except Exception as e:
            print(f"获取扫描信号量出错: {str(e)}")
            return

        try:
            # 进行扫描
            try:
                # 获取资产
                asset = await self.helpers.get_asset(asset_id)
                if not asset:
                    print(f"无法获取资产信息，资产ID: {asset_id}")
                    return

                print(f"成功获取资产: {asset.host}, ID: {asset.id}")

                # 创建扫描上下文
                context = {
                    'asset': asset,
                    'url': url,
                    'method': method,
                    'status_code': status_code,
                    'req_headers': req_headers,
                    'req_content': req_content,
                    'resp_headers': resp_headers,
                    'resp_content': resp_content,
                    'channel_layer': channel_layer,
                    'helpers': self.helpers,
                    'use_proxy': self.use_proxy,
                    'proxy_address': self.proxy_address,
                    'scan_timeout': self.scan_timeout,
                    # 添加对扫描器自身的引用
                    'scanner': self
                }

                # 更新扫描进度到25%
                await channel_layer.group_send(
                    'data_collection_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'scanning',
                            'message': f'准备模块扫描: {asset.host}',
                            'url': url,
                            'progress': 25
                        }
                    }
                )

                # 并行执行各个模块的扫描，添加超时控制
                tasks = [
                    self._scan_with_timeout(self.network_scanner.scan, context, "网络模块"),
                    self._scan_with_timeout(self.os_scanner.scan, context, "操作系统模块"),
                    self._scan_with_timeout(self.component_scanner.scan, context, "组件模块")
                ]

                # 更新扫描进度到50%
                await channel_layer.group_send(
                    'data_collection_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'scanning',
                            'message': f'扫描中: {asset.host}',
                            'url': url,
                            'progress': 50
                        }
                    }
                )

                # 等待所有任务完成，但设置总体超时
                with contextlib.suppress(asyncio.TimeoutError):
                    # 最多等待2分钟
                    results = await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=120  # 2分钟总超时
                    )

                    # 处理任务结果，检查是否有异常
                    for i, result in enumerate(results):
                        if isinstance(result, Exception) and not isinstance(result, asyncio.TimeoutError):
                            module_name = ["网络模块", "操作系统模块", "组件模块"][i]
                            print(f"{module_name}扫描出错: {str(result)}")

                # 更新扫描进度到90%
                await channel_layer.group_send(
                    'data_collection_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'scanning',
                            'message': f'完成扫描: {asset.host}',
                            'url': url,
                            'progress': 90
                        }
                    }
                )

                # 发送扫描完成事件
                await channel_layer.group_send(
                    'data_collection_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'completed',
                            'message': f'扫描完成: {asset.host}',
                            'url': url,
                            'progress': 100
                        }
                    }
                )

            except asyncio.TimeoutError:
                print(f"整体扫描超时: {url}")
                # 发送扫描超时事件
                await channel_layer.group_send(
                    'data_collection_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'error',
                            'message': f'扫描超时: {url}',
                            'url': url,
                            'progress': 0
                        }
                    }
                )
            except asyncio.CancelledError:
                print(f"扫描被取消: {url}")
                # 发送扫描取消事件
                await channel_layer.group_send(
                    'data_collection_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'cancelled',
                            'message': f'扫描已取消: {url}',
                            'url': url,
                            'progress': 0
                        }
                    }
                )
                raise  # 重新抛出取消异常
            except Exception as e:
                print(f"扫描过程中发生错误: {str(e)}")
                traceback.print_exc()

                # 发送扫描错误事件
                await channel_layer.group_send(
                    'data_collection_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'error',
                            'message': f'扫描错误: {str(e)}',
                            'url': url,
                            'progress': 0
                        }
                    }
                )

        except Exception as e:
            print(f"扫描执行出错: {str(e)}")
            traceback.print_exc()
        finally:
            # 释放信号量
            self.semaphore.release()
            # 清理pending_scans
            if url in self.pending_scans:
                self.pending_scans.pop(url)

    async def _scan_with_timeout(self, scan_func, context, module_name):
        """带超时的模块扫描包装器"""
        try:
            # 使用asyncio.wait_for设置单个模块的超时
            await asyncio.wait_for(
                scan_func(context),
                timeout=self.scan_timeout  # 使用配置的超时时间
            )
            print(f"{module_name}扫描完成")
            return True
        except asyncio.TimeoutError:
            print(f"{module_name}扫描超时（超过{self.scan_timeout}秒）")
            return asyncio.TimeoutError(f"{module_name}扫描超时")
        except asyncio.CancelledError:
            print(f"{module_name}扫描被取消")
            raise  # 重新抛出取消异常
        except Exception as e:
            print(f"{module_name}扫描出错: {str(e)}")
            traceback.print_exc()
            return e