import json
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .scanner import VulnScanner
from .models import VulnScanResult
from data_collection.models import Asset, SystemSettings, SkipTarget
from django.utils import timezone


class VulnScanConsumer(AsyncWebsocketConsumer):
    """
    WebSocket消费者：处理漏洞扫描模块的WebSocket连接
    """

    async def connect(self):
        """处理WebSocket连接"""
        # 将客户端添加到vuln_scan_scanner组
        await self.channel_layer.group_add(
            'vuln_scan_scanner',
            self.channel_name
        )

        # 将客户端添加到settings_update组
        await self.channel_layer.group_add(
            'settings_update',
            self.channel_name
        )

        # 接受WebSocket连接
        await self.accept()

        # 初始化扫描器
        self.scanner = VulnScanner()

        # 发送当前系统设置
        settings = await self.get_system_settings()
        await self.send(text_data=json.dumps({
            'type': 'settings',
            'data': settings
        }))

        # 发送当前跳过目标列表
        skip_targets = await self.get_skip_targets()
        await self.send(text_data=json.dumps({
            'type': 'skip_targets',
            'data': skip_targets
        }))

    async def disconnect(self, close_code):
        """处理WebSocket断开连接"""
        # 将客户端从vuln_scan_scanner组移除
        await self.channel_layer.group_discard(
            'vuln_scan_scanner',
            self.channel_name
        )

        # 将客户端从settings_update组移除
        await self.channel_layer.group_discard(
            'settings_update',
            self.channel_name
        )

    async def receive(self, text_data):
        """处理从WebSocket接收到的消息"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')

            if message_type == 'start_scan':
                # 开始扫描
                scan_options = data.get('options', {})
                await self.start_scan(scan_options)

            elif message_type == 'stop_scan':
                # 停止扫描
                await self.stop_scan()

            elif message_type == 'get_scan_results':
                # 获取扫描结果
                filters = data.get('filters', {})
                results = await self.get_scan_results(filters)
                await self.send(text_data=json.dumps({
                    'type': 'scan_results',
                    'data': results
                }))

        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': '无效的JSON数据'
            }))
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': str(e)
            }))

    async def proxy_data(self, event):
        """处理从代理接收到的HTTP数据"""
        # 获取HTTP数据
        data = event['data']

        # 处理数据（扫描）
        await self.process_proxy_data(data)

    async def settings_update(self, event):
        """处理系统设置更新事件"""
        # 获取新设置
        settings_data = event['data']

        # 更新扫描器设置
        await self.update_scanner_settings(settings_data)

        # 发送设置更新通知给客户端
        await self.send(text_data=json.dumps({
            'type': 'settings_update',
            'data': settings_data
        }))

    async def skip_target_update(self, event):
        """处理跳过目标更新事件"""
        # 获取操作类型和目标
        action = event['action']
        target = event['target']

        # 更新扫描器跳过目标
        if action == 'add':
            await self.add_scanner_skip_target(target)
        elif action == 'remove':
            await self.remove_scanner_skip_target(target)

        # 发送跳过目标更新通知给客户端
        await self.send(text_data=json.dumps({
            'type': 'skip_target_update',
            'action': action,
            'target': target
        }))

    async def scan_progress(self, event):
        """处理扫描进度更新事件"""
        # 发送扫描进度更新通知给客户端
        await self.send(text_data=json.dumps({
            'type': 'scan_progress',
            'data': event['data']
        }))

    async def scan_result(self, event):
        """处理扫描结果事件"""
        # 发送扫描结果通知给客户端
        await self.send(text_data=json.dumps({
            'type': 'scan_result',
            'data': event['data']
        }))

    # 以下是数据库操作方法

    @database_sync_to_async
    def get_system_settings(self):
        """获取系统设置"""
        settings, created = SystemSettings.objects.get_or_create(pk=1)
        return {
            'id': settings.id,
            'use_proxy': settings.use_proxy,
            'proxy_address': settings.proxy_address,
            'scan_timeout': settings.scan_timeout,
            'max_concurrent_scans': settings.max_concurrent_scans
        }

    @database_sync_to_async
    def get_skip_targets(self):
        """获取跳过目标列表"""
        targets = SkipTarget.objects.all()
        return [{'id': t.id, 'target': t.target, 'description': t.description} for t in targets]

    @database_sync_to_async
    def get_scan_results(self, filters):
        """获取扫描结果"""
        # 构建查询
        queryset = VulnScanResult.objects.all()

        # 应用过滤器
        if 'vuln_type' in filters:
            queryset = queryset.filter(vuln_type=filters['vuln_type'])
        if 'vuln_subtype' in filters:
            queryset = queryset.filter(vuln_subtype=filters['vuln_subtype'])
        if 'severity' in filters:
            queryset = queryset.filter(severity=filters['severity'])
        if 'host' in filters:
            queryset = queryset.filter(asset__host__icontains=filters['host'])
        if 'date_from' in filters:
            queryset = queryset.filter(scan_date__gte=filters['date_from'])
        if 'date_to' in filters:
            queryset = queryset.filter(scan_date__lte=filters['date_to'])

        # 序列化结果
        results = []
        for result in queryset:
            results.append({
                'id': result.id,
                'asset': result.asset.host,
                'asset_host': result.asset.host,
                'vuln_type': result.vuln_type,
                'vuln_type_display': result.get_vuln_type_display(),
                'vuln_subtype': result.vuln_subtype,
                'name': result.name,
                'description': result.description,
                'severity': result.severity,
                'severity_display': result.get_severity_display(),
                'url': result.url,
                'proof': result.proof,
                'scan_date': result.scan_date.isoformat(),
                'is_verified': result.is_verified,
                'parameter': result.parameter,
                'payload': result.payload
            })

        return results

    # 以下是扫描器操作方法

    async def start_scan(self, options):
        """开始扫描"""
        # 更新扫描器设置
        settings = await self.get_system_settings()
        await self.update_scanner_settings(settings)

        # 更新扫描器跳过目标
        skip_targets = await self.get_skip_targets()
        for target in skip_targets:
            await self.add_scanner_skip_target(target['target'])

        # 发送扫描开始通知
        await self.send(text_data=json.dumps({
            'type': 'scan_status',
            'status': 'started',
            'message': '扫描已开始'
        }))

    async def stop_scan(self):
        """停止扫描"""
        # 停止扫描器
        # (这里只是发送通知，实际的停止逻辑在scanner.py中)

        # 发送扫描停止通知
        await self.send(text_data=json.dumps({
            'type': 'scan_status',
            'status': 'stopped',
            'message': '扫描已停止'
        }))

    async def process_proxy_data(self, data):
        """处理代理数据"""
        # 调用扫描器处理数据
        try:
            # 解析URL获取主机名
            url = data.get('url', '')
            method = data.get('method', '')
            status_code = data.get('status_code', 0)
            req_headers = data.get('req_headers', {})
            req_content = data.get('req_content', '')
            resp_headers = data.get('resp_headers', {})
            resp_content = data.get('resp_content', '')

            # 创建或更新资产
            asset = await self.update_asset(url)

            # 启动扫描任务
            asyncio.create_task(self.scanner.scan_data(
                self.channel_layer,
                asset.id,
                url,
                method,
                status_code,
                req_headers,
                req_content,
                resp_headers,
                resp_content
            ))

        except Exception as e:
            print(f"处理代理数据时出错: {str(e)}")
            import traceback
            traceback.print_exc()

    @database_sync_to_async
    def update_asset(self, url):
        """更新资产"""
        from urllib.parse import urlparse
        # 从URL解析主机名
        parsed_url = urlparse(url)
        host = parsed_url.netloc

        # 创建或更新资产
        asset, created = Asset.objects.get_or_create(
            host=host,
            defaults={'first_seen': timezone.now()}
        )

        # 更新最后发现时间
        if not created:
            asset.last_seen = timezone.now()
            asset.save()

        return asset

    async def update_scanner_settings(self, settings):
        """更新扫描器设置"""
        self.scanner.use_proxy = settings.get('use_proxy', False)
        self.scanner.proxy_address = settings.get('proxy_address', 'http://localhost:7890')
        self.scanner.scan_timeout = settings.get('scan_timeout', 10)
        self.scanner.max_concurrent_scans = settings.get('max_concurrent_scans', 5)

    async def add_scanner_skip_target(self, target):
        """添加扫描器跳过目标"""
        self.scanner.skip_targets.add(target)

    async def remove_scanner_skip_target(self, target):
        """移除扫描器跳过目标"""
        if target in self.scanner.skip_targets:
            self.scanner.skip_targets.remove(target)