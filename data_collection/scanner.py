"""
扫描器主模块：负责协调各个子模块进行扫描
"""
import asyncio
from urllib.parse import urlparse
from django.utils import timezone
from asgiref.sync import sync_to_async

from .models import Asset, ScanResult
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

        # 初始化各个扫描模块
        self.network_scanner = NetworkScanner()
        self.os_scanner = OSScanner()
        self.component_scanner = ComponentScanner()
        self.helpers = ScanHelpers()

        # 添加已扫描资产跟踪
        self.scanned_assets = set()  # 记录已扫描资产ID

    # 添加重置扫描状态的方法
    def reset_scan_state(self):
        """重置扫描状态，清除缓存"""
        self.scanned_assets.clear()  # 清除资产记录
        self.network_scanner.clear_cache() if hasattr(self.network_scanner, 'clear_cache') else None
        print("扫描状态已重置")

    async def scan_data(self, channel_layer, asset_id, url, method, status_code, req_headers, req_content, resp_headers,
                        resp_content):
        """
        扫描数据

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
        # 添加调试信息
        print(f"开始扫描资产{asset_id}: {url}, 方法: {method}, 状态码: {status_code}")

        # 临时清除缓存，确保所有扫描都执行
        self.scanned_assets.clear()

        # 解析URL获取主机名
        parsed_url = urlparse(url)
        host = parsed_url.netloc

        # 检查是否需要跳过此目标
        if host in self.skip_targets:
            print(f"跳过目标: {host} (在跳过列表中)")
            return

        # 获取资产
        asset = await self.helpers.get_asset(asset_id)
        if not asset:
            print(f"无法获取资产信息，资产ID: {asset_id}")
            return

        print(f"成功获取资产: {asset.host}, ID: {asset.id}")

        # 检查是否已经处理过该资产的端口扫描
        asset_key = f"{asset_id}-port-scan"
        if asset_key in self.scanned_assets:
            # 如果已处理过，只进行非端口扫描的检查
            print(f"跳过资产{asset_id}的重复端口扫描")
        else:
            # 标记该资产已处理端口扫描
            self.scanned_assets.add(asset_key)
            print(f"已将资产{asset_id}添加到端口扫描缓存")

        # 使用信号量控制并发扫描数量
        async with self.semaphore:
            # 设置信号量大小（可能在运行时被修改）
            self.semaphore._value = self.max_concurrent_scans

            # 进行扫描
            try:
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
                    'scan_timeout': self.scan_timeout
                }

                # 发送扫描开始事件
                await channel_layer.group_send(
                    'data_collection_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'scanning',
                            'message': f'正在扫描 {host}',
                            'url': url,
                            'progress': 0
                        }
                    }
                )

                # 并行执行各个模块的扫描
                tasks = [
                    self.network_scanner.scan(context),
                    self.os_scanner.scan(context),
                    self.component_scanner.scan(context)
                ]
                await asyncio.gather(*tasks)

                # 发送扫描完成事件
                await channel_layer.group_send(
                    'data_collection_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'completed',
                            'message': f'扫描完成: {host}',
                            'url': url,
                            'progress': 100
                        }
                    }
                )

            except Exception as e:
                print(f"扫描过程中发生错误: {str(e)}")
                import traceback
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