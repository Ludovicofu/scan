"""
修复 data_collection/consumers.py 中的结果重复问题和资产显示问题
该文件负责WebSocket通信和消息分发，是解决重复通知的关键
"""
import json
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .scanner import DataCollectionScanner
from .models import Asset, ScanResult, SystemSettings, SkipTarget
from django.utils import timezone


class DataCollectionConsumer(AsyncWebsocketConsumer):
    """
    WebSocket消费者：处理数据收集模块的WebSocket连接
    """
    # 添加静态缓存用于跨连接去重
    _global_result_cache = set()  # 格式: (asset_host, module, description, rule_type)

    async def connect(self):
        """处理WebSocket连接"""
        # 记录连接尝试
        print(f"WebSocket连接尝试: {self.scope['path']}")

        # 将客户端添加到data_collection_scanner组
        await self.channel_layer.group_add(
            'data_collection_scanner',
            self.channel_name
        )

        # 将客户端添加到settings_update组
        await self.channel_layer.group_add(
            'settings_update',
            self.channel_name
        )

        # 接受WebSocket连接
        await self.accept()
        print("WebSocket连接已接受")

        # 初始化扫描器
        self.scanner = DataCollectionScanner()

        # 添加实例级别的本地结果缓存
        self.local_result_cache = set()

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
        # 将客户端从data_collection_scanner组移除
        await self.channel_layer.group_discard(
            'data_collection_scanner',
            self.channel_name
        )

        # 将客户端从settings_update组移除
        await self.channel_layer.group_discard(
            'settings_update',
            self.channel_name
        )

        # 断开连接时清理本地缓存
        self.local_result_cache.clear()

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

            elif message_type == 'reset_cache':
                # 重置缓存
                await self.reset_caches(data.get('reset_global', False))
                await self.send(text_data=json.dumps({
                    'type': 'cache_reset',
                    'status': 'success',
                    'message': '扫描缓存已重置'
                }))

        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': '无效的JSON数据'
            }))
        except Exception as e:
            print(f"接收WebSocket消息时出错: {str(e)}")
            import traceback
            traceback.print_exc()
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
        """处理扫描结果事件，添加去重逻辑"""
        # 获取数据
        result_data = event['data']

        # 如果没有关键字段，直接返回
        if not result_data.get('asset') or not result_data.get('module') or not result_data.get('description'):
            print("扫描结果数据不完整，跳过")
            return

        # 创建结果缓存键 - 使用asset_host而不是asset
        cache_key = (
            result_data.get('asset_host', ''),  # 使用asset_host而不是asset
            result_data.get('module', ''),
            result_data.get('description', ''),
            result_data.get('rule_type', '')
        )

        # 检查全局缓存和本地缓存中是否存在
        if cache_key in DataCollectionConsumer._global_result_cache or cache_key in self.local_result_cache:
            print(f"跳过重复结果: {cache_key}")
            return

        # 添加到全局缓存和本地缓存
        DataCollectionConsumer._global_result_cache.add(cache_key)
        self.local_result_cache.add(cache_key)

        # 添加结果ID如果存在
        if 'id' in result_data:
            result_id = result_data['id']
            print(f"发送扫描结果 ID: {result_id}, 描述: {result_data.get('description')}")
        else:
            print(f"发送扫描结果: {result_data.get('description')}")

        # 发送扫描结果通知给客户端
        await self.send(text_data=json.dumps({
            'type': 'scan_result',
            'data': result_data
        }))

    # 添加重置缓存的方法
    async def reset_caches(self, reset_global=False):
        """重置结果缓存"""
        # 清除本地缓存
        self.local_result_cache.clear()

        # 重置扫描器缓存
        self.scanner.reset_scan_state()

        # 如果需要，清除全局缓存
        if reset_global:
            DataCollectionConsumer._global_result_cache.clear()
            print("已重置全局结果缓存")

        print("已重置本地结果缓存和扫描器状态")

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
        queryset = ScanResult.objects.all()

        # 应用过滤器
        if 'scan_type' in filters:
            queryset = queryset.filter(scan_type=filters['scan_type'])
        if 'module' in filters:
            queryset = queryset.filter(module=filters['module'])
        if 'host' in filters:
            queryset = queryset.filter(asset__host__icontains=filters['host'])
        if 'date_from' in filters:
            queryset = queryset.filter(scan_date__gte=filters['date_from'])
        if 'date_to' in filters:
            queryset = queryset.filter(scan_date__lte=filters['date_to'])

        # 序列化结果
        results = []
        for result in queryset:
            # 添加端口扫描结果的特殊处理
            is_port_scan = result.rule_type == 'port'
            port_numbers = []
            port_display = ""

            if is_port_scan:
                # 解析端口号
                for line in result.match_value.split('\n'):
                    if ':' in line:
                        port = line.split(':', 1)[0].strip()
                        if port.isdigit():
                            port_numbers.append(port)
                port_display = ", ".join(port_numbers) if port_numbers else "未知端口"

            # 创建结果对象 - 修改：确保asset字段是主机名而不是ID
            result_data = {
                'id': result.id,
                'asset': result.asset.host,  # 使用主机名而不是ID
                'asset_host': result.asset.host,  # 明确添加资产主机名
                'module': result.module,
                'module_display': result.get_module_display(),
                'scan_type': result.scan_type,
                'scan_type_display': result.get_scan_type_display(),
                'description': result.description,
                'rule_type': result.rule_type,
                'match_value': result.match_value,
                'behavior': result.behavior,
                # 添加请求和响应数据
                'request_data': result.request_data,
                'response_data': result.response_data,
                'scan_date': result.scan_date.isoformat(),
                # 添加端口扫描结果的特殊字段
                'is_port_scan': is_port_scan,
                'port_numbers': port_numbers,
                'port_display': port_display
            }
            results.append(result_data)

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

        # 重置扫描状态 - 在开始新的扫描任务前清除缓存
        self.scanner.reset_scan_state()

        # 清除本地结果缓存，但保留全局缓存
        self.local_result_cache.clear()

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
        try:
            # 解析URL获取主机名
            url = data.get('url', '')
            method = data.get('method', '')
            status_code = data.get('status_code', 0)
            req_headers = data.get('req_headers', {})
            req_content = data.get('req_content', '')
            resp_headers = data.get('resp_headers', {})
            resp_content = data.get('resp_content', '')

            print(f"收到代理数据: URL={url}, 方法={method}, 状态码={status_code}")

            # 检查URL是否有效
            if not url:
                print("URL为空，跳过处理")
                return

            # 创建或更新资产
            asset = await self.update_asset(url)

            if asset:
                print(f"准备扫描资产: {asset.host}, ID={asset.id}")

                # 启动扫描任务
                task = asyncio.create_task(
                    self.scanner.scan_data(
                        self.channel_layer,
                        asset.id,
                        url,
                        method,
                        status_code,
                        req_headers,
                        req_content,
                        resp_headers,
                        resp_content
                    )
                )
                print(f"扫描任务已创建: {url}")
            else:
                print("资产创建/更新失败，无法启动扫描")

        except Exception as e:
            print(f"处理代理数据时出错: {str(e)}")
            import traceback
            traceback.print_exc()

    @database_sync_to_async
    def update_asset(self, url):
        """更新资产"""
        from urllib.parse import urlparse
        try:
            # 从URL解析主机名，处理带端口号的情况
            parsed_url = urlparse(url)
            host = parsed_url.netloc

            # 修正: 如果netloc包含端口号，只取域名部分
            if ':' in host:
                host = host.split(':')[0]

            if not host:
                print(f"无法从URL解析主机名: {url}")
                return None

            # 创建或更新资产
            asset, created = Asset.objects.get_or_create(
                host=host,
                defaults={'first_seen': timezone.now()}
            )

            # 更新最后发现时间
            if not created:
                asset.last_seen = timezone.now()
                asset.save()
                print(f"更新资产: {host}, ID={asset.id}")
            else:
                print(f"创建新资产: {host}, ID={asset.id}")

            return asset
        except Exception as e:
            print(f"更新资产失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

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