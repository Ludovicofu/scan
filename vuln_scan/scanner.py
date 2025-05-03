# vuln_scan/scanner.py
import asyncio
from urllib.parse import urlparse
from django.utils import timezone
from asgiref.sync import sync_to_async
from data_collection.models import Asset
from .models import VulnScanResult

# 导入各个漏洞扫描模块
from .modules.sql_injection_scanner import SqlInjectionScanner
from .modules.xss_scanner import XssScanner  # 引入XSS扫描模块
from .modules.file_inclusion_scanner import FileInclusionScanner  # 引入文件包含扫描模块


class VulnScanner:
    """
    漏洞扫描器：负责进行漏洞扫描检测
    整合了多种漏洞类型的扫描模块
    """

    def __init__(self):
        """初始化扫描器"""
        self.is_scanning = False
        self.use_proxy = False
        self.proxy_address = "http://localhost:7890"
        self.scan_timeout = 30  # 默认扫描超时时间（秒）
        self.max_concurrent_scans = 5  # 默认最大并发扫描数
        self.skip_targets = set()  # 要跳过的目标集合
        self.semaphore = asyncio.Semaphore(5)  # 默认并发数控制

        # 初始化各个漏洞扫描模块
        self.sql_injection_scanner = SqlInjectionScanner()
        self.xss_scanner = XssScanner()  # 初始化XSS扫描器
        self.file_inclusion_scanner = FileInclusionScanner()  # 初始化文件包含扫描器
        # 以后可以添加其他类型的扫描器
        # self.command_injection_scanner = CommandInjectionScanner()
        # 等等...

        # 已扫描的URL记录
        self.scanned_urls = set()

    def reset_scan_state(self):
        """重置扫描状态，清除缓存"""
        self.scanned_urls.clear()

        # 重置各个扫描模块的缓存
        if hasattr(self.sql_injection_scanner, 'clear_cache'):
            self.sql_injection_scanner.clear_cache()

        # 重置XSS扫描模块的缓存
        if hasattr(self.xss_scanner, 'clear_cache'):
            self.xss_scanner.clear_cache()

        # 重置文件包含扫描模块的缓存
        if hasattr(self.file_inclusion_scanner, 'clear_cache'):
            self.file_inclusion_scanner.clear_cache()

        # 以后可以添加其他类型的扫描器缓存清理
        # if hasattr(self.command_injection_scanner, 'clear_cache'):
        #     self.command_injection_scanner.clear_cache()
        # 等等...

        print("漏洞扫描器状态已重置")

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
        # 解析URL获取主机名
        parsed_url = urlparse(url)
        host = parsed_url.netloc

        # 检查是否需要跳过此目标
        if host in self.skip_targets:
            print(f"跳过目标: {host} (在跳过列表中)")
            return

        # 检查URL是否已扫描
        if url in self.scanned_urls:
            print(f"跳过已扫描URL: {url}")
            return

        # 标记URL为已扫描
        self.scanned_urls.add(url)

        # 获取资产
        asset = await self.get_asset(asset_id)
        if not asset:
            print(f"无法获取资产信息，资产ID: {asset_id}")
            return

        # 使用信号量控制并发扫描数量
        async with self.semaphore:
            # 设置信号量大小
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
                    'use_proxy': self.use_proxy,
                    'proxy_address': self.proxy_address,
                    'scan_timeout': self.scan_timeout
                }

                # 发送扫描开始事件
                await channel_layer.group_send(
                    'vuln_scan_scanner',
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

                # 并行执行各个漏洞类型的扫描
                tasks = [
                    self.sql_injection_scanner.scan(context),
                    self.xss_scanner.scan(context),  # 添加XSS扫描任务
                    self.file_inclusion_scanner.scan(context),  # 添加文件包含扫描任务
                    # 以后可以添加其他类型的扫描
                    # self.command_injection_scanner.scan(context),
                    # 等等...
                ]

                # 等待所有任务完成或有一个失败
                scan_results = await asyncio.gather(*tasks, return_exceptions=True)

                # 处理扫描结果
                vuln_results = []

                # 处理SQL注入扫描结果
                if not isinstance(scan_results[0], Exception):
                    vuln_results.extend(scan_results[0])
                else:
                    print(f"SQL注入扫描出错: {str(scan_results[0])}")

                # 处理XSS扫描结果
                if not isinstance(scan_results[1], Exception):
                    vuln_results.extend(scan_results[1])
                else:
                    print(f"XSS扫描出错: {str(scan_results[1])}")

                # 处理文件包含扫描结果
                if not isinstance(scan_results[2], Exception):
                    vuln_results.extend(scan_results[2])
                else:
                    print(f"文件包含扫描出错: {str(scan_results[2])}")

                # 以后可以添加其他类型的扫描结果处理
                # if not isinstance(scan_results[3], Exception):
                #     vuln_results.extend(scan_results[3])
                # else:
                #     print(f"命令注入扫描出错: {str(scan_results[3])}")
                # 等等...

                # 保存漏洞结果
                for result in vuln_results:
                    vuln_result = await self.save_vuln_result(
                        asset=asset,
                        vuln_type=result['vuln_type'],
                        vuln_subtype=result.get('vuln_subtype'),
                        name=result['name'],
                        description=result['description'],
                        severity=result['severity'],
                        url=result['url'],
                        request=result.get('request'),
                        response=result.get('response'),
                        proof=result.get('proof'),
                        parameter=result.get('parameter'),
                        payload=result.get('payload')
                    )

                    # 发送漏洞结果事件
                    if vuln_result:
                        await channel_layer.group_send(
                            'vuln_scan_scanner',
                            {
                                'type': 'scan_result',
                                'data': {
                                    'id': vuln_result.id,
                                    'asset': asset.host,
                                    'vuln_type': vuln_result.vuln_type,
                                    'vuln_type_display': vuln_result.get_vuln_type_display(),
                                    'vuln_subtype': vuln_result.vuln_subtype,
                                    'name': vuln_result.name,
                                    'description': vuln_result.description,
                                    'severity': vuln_result.severity,
                                    'severity_display': vuln_result.get_severity_display(),
                                    'url': vuln_result.url,
                                    'request': vuln_result.request,
                                    'response': vuln_result.response,
                                    'proof': vuln_result.proof,
                                    'scan_date': vuln_result.scan_date.isoformat(),
                                    'is_verified': vuln_result.is_verified,
                                    'parameter': vuln_result.parameter,
                                    'payload': vuln_result.payload
                                }
                            }
                        )

                # 发送扫描完成事件
                await channel_layer.group_send(
                    'vuln_scan_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'completed',
                            'message': f'扫描完成: {host}, 发现 {len(vuln_results)} 个漏洞',
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
                    'vuln_scan_scanner',
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

    # 辅助方法

    @sync_to_async
    def get_asset(self, asset_id):
        """获取资产"""
        try:
            return Asset.objects.get(id=asset_id)
        except Asset.DoesNotExist:
            print(f"资产不存在，ID: {asset_id}")
            return None
        except Exception as e:
            print(f"获取资产失败: {str(e)}")
            return None

    @sync_to_async
    def save_vuln_result(self, asset, vuln_type, vuln_subtype, name, description, severity, url, request,
                         response, proof, parameter=None, payload=None):
        """保存漏洞结果"""
        try:
            # 检查是否已存在相同的漏洞结果
            existing_results = VulnScanResult.objects.filter(
                asset=asset,
                vuln_type=vuln_type,
                vuln_subtype=vuln_subtype,
                url=url,
                name=name
            )

            # 如果不存在相同的结果，才创建新记录
            if not existing_results.exists():
                return VulnScanResult.objects.create(
                    asset=asset,
                    vuln_type=vuln_type,
                    vuln_subtype=vuln_subtype,
                    name=name,
                    description=description,
                    severity=severity,
                    url=url,
                    request=request,
                    response=response,
                    proof=proof,
                    parameter=parameter,
                    payload=payload,
                    scan_date=timezone.now()
                )
            else:
                # 返回已存在的记录
                return existing_results.first()
        except Exception as e:
            # 如果保存失败，记录错误
            print(f"保存漏洞结果失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return None