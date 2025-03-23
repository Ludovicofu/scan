import asyncio
from urllib.parse import urlparse
from asgiref.sync import sync_to_async
from django.utils import timezone
from data_collection.models import Asset
from .models import VulnScanResult
from rules.models import VulnScanRule


class VulnScanner:
    """
    漏洞扫描器：负责进行漏洞扫描检测
    注意：当前仅为占位，没有实现具体的扫描逻辑
    """

    def __init__(self):
        """初始化扫描器"""
        self.is_scanning = False
        self.use_proxy = False
        self.proxy_address = "http://localhost:7890"
        self.scan_timeout = 3000
        self.max_concurrent_scans = 5
        self.skip_targets = set()
        self.semaphore = asyncio.Semaphore(5)  # 默认并发数为5

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
            return

        # 获取资产
        asset = await self.get_asset(asset_id)

        # 使用信号量控制并发扫描数量
        async with self.semaphore:
            # 设置信号量大小
            self.semaphore._value = self.max_concurrent_scans

            # 进行被动扫描
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
                    'channel_layer': channel_layer
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

                # 获取被动扫描规则
                passive_rules = await self.get_rules('passive')

                # 进行被动扫描（实际逻辑未实现）
                # TODO: 实现具体的漏洞扫描逻辑

                # 示例：假设发现了一个XSS漏洞
                # 这里仅作为示例，实际应用中应根据规则进行真正的漏洞检测
                if 'alert(' in resp_content.lower() or '<script>' in resp_content.lower():
                    vuln_result = await self.save_vuln_result(
                        asset=asset,
                        vuln_type='xss',
                        scan_type='passive',
                        name='反射型XSS漏洞',
                        description='页面响应中包含可能导致XSS的内容',
                        severity='medium',
                        url=url,
                        request=f"Method: {method}\nHeaders: {req_headers}\nContent: {req_content}",
                        response=f"Status: {status_code}\nHeaders: {resp_headers}\nContent: {resp_content[:500]}...",
                        proof='在响应内容中发现可疑的JavaScript代码'
                    )

                    # 发送扫描结果事件
                    await channel_layer.group_send(
                        'vuln_scan_scanner',
                        {
                            'type': 'scan_result',
                            'data': {
                                'id': vuln_result.id,
                                'asset': asset.host,
                                'vuln_type': 'xss',
                                'vuln_type_display': '跨站脚本攻击（XSS）',
                                'scan_type': 'passive',
                                'scan_type_display': '被动扫描',
                                'name': '反射型XSS漏洞',
                                'description': '页面响应中包含可能导致XSS的内容',
                                'severity': 'medium',
                                'severity_display': '中',
                                'url': url,
                                'proof': '在响应内容中发现可疑的JavaScript代码',
                                'scan_date': timezone.now().isoformat(),
                                'is_verified': False
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
                            'message': f'扫描完成: {host}',
                            'url': url,
                            'progress': 100
                        }
                    }
                )

            except Exception as e:
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
        return Asset.objects.get(id=asset_id)

    @sync_to_async
    def get_rules(self, scan_type):
        """获取规则"""
        rules = VulnScanRule.objects.filter(
            scan_type=scan_type,
            is_enabled=True
        )

        result = []
        for rule in rules:
            result.append({
                'id': rule.id,
                'vuln_type': rule.vuln_type,
                'name': rule.name,
                'description': rule.description,
                'rule_content': rule.rule_content
            })

        return result

    @sync_to_async
    def save_vuln_result(self, asset, vuln_type, scan_type, name, description, severity, url, request, response, proof):
        """保存漏洞结果"""
        # 检查是否已存在相同的漏洞结果
        existing_results = VulnScanResult.objects.filter(
            asset=asset,
            vuln_type=vuln_type,
            url=url,
            name=name
        )

        # 如果不存在相同的结果，才创建新记录
        if not existing_results.exists():
            return VulnScanResult.objects.create(
                asset=asset,
                vuln_type=vuln_type,
                scan_type=scan_type,
                name=name,
                description=description,
                severity=severity,
                url=url,
                request=request,
                response=response,
                proof=proof,
                scan_date=timezone.now()
            )
        else:
            # 返回已存在的记录
            return existing_results.first()