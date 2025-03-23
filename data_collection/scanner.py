import asyncio
import json
from urllib.parse import urlparse
from asgiref.sync import sync_to_async
from django.utils import timezone
from .models import Asset, ScanResult
from .network_info import NetworkInfoScanner
from .os_info import OSInfoScanner
from .component_info import ComponentInfoScanner
from rules.models import InfoCollectionRule


class DataCollectionScanner:
    """
    数据采集扫描器：负责协调各个扫描模块进行扫描
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

        # 初始化各个扫描模块
        self.network_scanner = NetworkInfoScanner()
        self.os_scanner = OSInfoScanner()
        self.component_scanner = ComponentInfoScanner()

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
                    self.scan_network_info(context),
                    self.scan_os_info(context),
                    self.scan_component_info(context)
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

    async def scan_network_info(self, context):
        """
        扫描网络信息

        参数:
            context: 扫描上下文
        """
        # 获取上下文数据
        asset = context['asset']
        url = context['url']
        status_code = context['status_code']
        req_headers = context['req_headers']
        resp_headers = context['resp_headers']
        resp_content = context['resp_content']
        channel_layer = context['channel_layer']

        # 获取被动扫描规则
        passive_rules = await self.get_rules('network', 'passive')

        # 进行被动扫描
        for rule in passive_rules:
            # 获取规则详情
            rule_id = rule['id']
            description = rule['description']
            rule_type = rule['rule_type']
            match_values = rule['match_values']

            # 根据规则类型进行匹配
            match_results = []
            if rule_type == 'status_code':
                # 状态码判断
                if str(status_code) in match_values:
                    match_results.append(str(status_code))

            elif rule_type == 'response_content':
                # 响应内容匹配
                for match_value in match_values:
                    if match_value.lower() in resp_content.lower():
                        match_results.append(match_value)

            elif rule_type == 'header':
                # HTTP头匹配
                for match_value in match_values:
                    header_name, header_value = match_value.split(':', 1) if ':' in match_value else (match_value, '')
                    header_name = header_name.strip()
                    header_value = header_value.strip()

                    # 检查请求头
                    if header_name in req_headers:
                        if not header_value or header_value.lower() in req_headers[header_name].lower():
                            match_results.append(match_value)

                    # 检查响应头
                    if header_name in resp_headers:
                        if not header_value or header_value.lower() in resp_headers[header_name].lower():
                            match_results.append(match_value)

            # 如果有匹配结果，保存扫描结果
            if match_results:
                await self.save_scan_result(
                    asset=asset,
                    module='network',
                    scan_type='passive',
                    description=description,
                    rule_type=rule_type,
                    match_value='\n'.join(match_results),
                    behavior=None
                )

                # 发送扫描结果事件
                await channel_layer.group_send(
                    'data_collection_scanner',
                    {
                        'type': 'scan_result',
                        'data': {
                            'asset': asset.host,
                            'module': 'network',
                            'module_display': '网络信息',
                            'scan_type': 'passive',
                            'scan_type_display': '被动扫描',
                            'description': description,
                            'rule_type': rule_type,
                            'match_value': '\n'.join(match_results),
                            'behavior': None,
                            'scan_date': timezone.now().isoformat()
                        }
                    }
                )

        # 使用网络信息扫描器进行主动扫描
        active_rules = await self.get_rules('network', 'active')

        # 限制主动扫描的超时时间
        for rule in active_rules:
            rule_id = rule['id']
            description = rule['description']
            behaviors = rule['behaviors']
            rule_type = rule['rule_type']
            match_values = rule['match_values']

            # 对每个行为进行扫描
            for behavior in behaviors:
                try:
                    # 设置超时
                    scan_result = await asyncio.wait_for(
                        self.network_scanner.scan(
                            url=url,
                            behavior=behavior,
                            rule_type=rule_type,
                            match_values=match_values,
                            use_proxy=self.use_proxy,
                            proxy_address=self.proxy_address
                        ),
                        timeout=self.scan_timeout
                    )

                    # 如果有匹配结果，保存扫描结果
                    if scan_result:
                        match_value = scan_result.get('match_value', '')

                        await self.save_scan_result(
                            asset=asset,
                            module='network',
                            scan_type='active',
                            description=description,
                            rule_type=rule_type,
                            match_value=match_value,
                            behavior=behavior
                        )

                        # 发送扫描结果事件
                        await channel_layer.group_send(
                            'data_collection_scanner',
                            {
                                'type': 'scan_result',
                                'data': {
                                    'asset': asset.host,
                                    'module': 'network',
                                    'module_display': '网络信息',
                                    'scan_type': 'active',
                                    'scan_type_display': '主动扫描',
                                    'description': description,
                                    'rule_type': rule_type,
                                    'match_value': match_value,
                                    'behavior': behavior,
                                    'scan_date': timezone.now().isoformat()
                                }
                            }
                        )

                except asyncio.TimeoutError:
                    # 扫描超时，跳过此行为
                    continue
                except Exception as e:
                    # 扫描出错，跳过此行为
                    print(f"网络信息扫描出错: {str(e)}")
                    continue

    async def scan_os_info(self, context):
        """
        扫描操作系统信息

        参数:
            context: 扫描上下文
        """
        # 获取上下文数据
        asset = context['asset']
        url = context['url']
        status_code = context['status_code']
        req_headers = context['req_headers']
        resp_headers = context['resp_headers']
        resp_content = context['resp_content']
        channel_layer = context['channel_layer']

        # 获取被动扫描规则
        passive_rules = await self.get_rules('os', 'passive')

        # 进行被动扫描
        for rule in passive_rules:
            # 获取规则详情
            rule_id = rule['id']
            description = rule['description']
            rule_type = rule['rule_type']
            match_values = rule['match_values']

            # 根据规则类型进行匹配
            match_results = []
            if rule_type == 'status_code':
                # 状态码判断
                if str(status_code) in match_values:
                    match_results.append(str(status_code))

            elif rule_type == 'response_content':
                # 响应内容匹配
                for match_value in match_values:
                    if match_value.lower() in resp_content.lower():
                        match_results.append(match_value)

            elif rule_type == 'header':
                # HTTP头匹配
                for match_value in match_values:
                    header_name, header_value = match_value.split(':', 1) if ':' in match_value else (match_value, '')
                    header_name = header_name.strip()
                    header_value = header_value.strip()

                    # 检查请求头
                    if header_name in req_headers:
                        if not header_value or header_value.lower() in req_headers[header_name].lower():
                            match_results.append(match_value)

                    # 检查响应头
                    if header_name in resp_headers:
                        if not header_value or header_value.lower() in resp_headers[header_name].lower():
                            match_results.append(match_value)

            # 如果有匹配结果，保存扫描结果
            if match_results:
                await self.save_scan_result(
                    asset=asset,
                    module='os',
                    scan_type='passive',
                    description=description,
                    rule_type=rule_type,
                    match_value='\n'.join(match_results),
                    behavior=None
                )

                # 发送扫描结果事件
                await channel_layer.group_send(
                    'data_collection_scanner',
                    {
                        'type': 'scan_result',
                        'data': {
                            'asset': asset.host,
                            'module': 'os',
                            'module_display': '操作系统信息',
                            'scan_type': 'passive',
                            'scan_type_display': '被动扫描',
                            'description': description,
                            'rule_type': rule_type,
                            'match_value': '\n'.join(match_results),
                            'behavior': None,
                            'scan_date': timezone.now().isoformat()
                        }
                    }
                )

        # 使用操作系统信息扫描器进行主动扫描
        active_rules = await self.get_rules('os', 'active')

        # 对每个规则进行扫描
        for rule in active_rules:
            rule_id = rule['id']
            description = rule['description']
            behaviors = rule['behaviors']
            rule_type = rule['rule_type']
            match_values = rule['match_values']

            # 对每个行为进行扫描
            for behavior in behaviors:
                try:
                    # 设置超时
                    scan_result = await asyncio.wait_for(
                        self.os_scanner.scan(
                            url=url,
                            behavior=behavior,
                            rule_type=rule_type,
                            match_values=match_values,
                            use_proxy=self.use_proxy,
                            proxy_address=self.proxy_address
                        ),
                        timeout=self.scan_timeout
                    )

                    # 如果有匹配结果，保存扫描结果
                    if scan_result:
                        match_value = scan_result.get('match_value', '')

                        await self.save_scan_result(
                            asset=asset,
                            module='os',
                            scan_type='active',
                            description=description,
                            rule_type=rule_type,
                            match_value=match_value,
                            behavior=behavior
                        )

                        # 发送扫描结果事件
                        await channel_layer.group_send(
                            'data_collection_scanner',
                            {
                                'type': 'scan_result',
                                'data': {
                                    'asset': asset.host,
                                    'module': 'os',
                                    'module_display': '操作系统信息',
                                    'scan_type': 'active',
                                    'scan_type_display': '主动扫描',
                                    'description': description,
                                    'rule_type': rule_type,
                                    'match_value': match_value,
                                    'behavior': behavior,
                                    'scan_date': timezone.now().isoformat()
                                }
                            }
                        )

                except asyncio.TimeoutError:
                    # 扫描超时，跳过此行为
                    continue
                except Exception as e:
                    # 扫描出错，跳过此行为
                    print(f"操作系统信息扫描出错: {str(e)}")
                    continue

    async def scan_component_info(self, context):
        """
        扫描组件与服务信息

        参数:
            context: 扫描上下文
        """
        # 获取上下文数据
        asset = context['asset']
        url = context['url']
        status_code = context['status_code']
        req_headers = context['req_headers']
        resp_headers = context['resp_headers']
        resp_content = context['resp_content']
        channel_layer = context['channel_layer']

        # 获取被动扫描规则
        passive_rules = await self.get_rules('component', 'passive')

        # 进行被动扫描
        for rule in passive_rules:
            # 获取规则详情
            rule_id = rule['id']
            description = rule['description']
            rule_type = rule['rule_type']
            match_values = rule['match_values']

            # 根据规则类型进行匹配
            match_results = []
            if rule_type == 'status_code':
                # 状态码判断
                if str(status_code) in match_values:
                    match_results.append(str(status_code))

            elif rule_type == 'response_content':
                # 响应内容匹配
                for match_value in match_values:
                    if match_value.lower() in resp_content.lower():
                        match_results.append(match_value)

            elif rule_type == 'header':
                # HTTP头匹配
                for match_value in match_values:
                    header_name, header_value = match_value.split(':', 1) if ':' in match_value else (match_value, '')
                    header_name = header_name.strip()
                    header_value = header_value.strip()

                    # 检查请求头
                    if header_name in req_headers:
                        if not header_value or header_value.lower() in req_headers[header_name].lower():
                            match_results.append(match_value)

                    # 检查响应头
                    if header_name in resp_headers:
                        if not header_value or header_value.lower() in resp_headers[header_name].lower():
                            match_results.append(match_value)

            # 如果有匹配结果，保存扫描结果
            if match_results:
                await self.save_scan_result(
                    asset=asset,
                    module='component',
                    scan_type='passive',
                    description=description,
                    rule_type=rule_type,
                    match_value='\n'.join(match_results),
                    behavior=None
                )

                # 发送扫描结果事件
                await channel_layer.group_send(
                    'data_collection_scanner',
                    {
                        'type': 'scan_result',
                        'data': {
                            'asset': asset.host,
                            'module': 'component',
                            'module_display': '组件与服务信息',
                            'scan_type': 'passive',
                            'scan_type_display': '被动扫描',
                            'description': description,
                            'rule_type': rule_type,
                            'match_value': '\n'.join(match_results),
                            'behavior': None,
                            'scan_date': timezone.now().isoformat()
                        }
                    }
                )

        # 使用组件信息扫描器进行主动扫描
        active_rules = await self.get_rules('component', 'active')

        # 对每个规则进行扫描
        for rule in active_rules:
            rule_id = rule['id']
            description = rule['description']
            behaviors = rule['behaviors']
            rule_type = rule['rule_type']
            match_values = rule['match_values']

            # 对每个行为进行扫描
            for behavior in behaviors:
                try:
                    # 设置超时
                    scan_result = await asyncio.wait_for(
                        self.component_scanner.scan(
                            url=url,
                            behavior=behavior,
                            rule_type=rule_type,
                            match_values=match_values,
                            use_proxy=self.use_proxy,
                            proxy_address=self.proxy_address
                        ),
                        timeout=self.scan_timeout
                    )

                    # 如果有匹配结果，保存扫描结果
                    if scan_result:
                        match_value = scan_result.get('match_value', '')

                        await self.save_scan_result(
                            asset=asset,
                            module='component',
                            scan_type='active',
                            description=description,
                            rule_type=rule_type,
                            match_value=match_value,
                            behavior=behavior
                        )

                        # 发送扫描结果事件
                        await channel_layer.group_send(
                            'data_collection_scanner',
                            {
                                'type': 'scan_result',
                                'data': {
                                    'asset': asset.host,
                                    'module': 'component',
                                    'module_display': '组件与服务信息',
                                    'scan_type': 'active',
                                    'scan_type_display': '主动扫描',
                                    'description': description,
                                    'rule_type': rule_type,
                                    'match_value': match_value,
                                    'behavior': behavior,
                                    'scan_date': timezone.now().isoformat()
                                }
                            }
                        )

                except asyncio.TimeoutError:
                    # 扫描超时，跳过此行为
                    continue
                except Exception as e:
                    # 扫描出错，跳过此行为
                    print(f"组件与服务信息扫描出错: {str(e)}")
                    continue

    # 辅助方法

    @sync_to_async
    def get_asset(self, asset_id):
        """获取资产"""
        return Asset.objects.get(id=asset_id)

    @sync_to_async
    def get_rules(self, module, scan_type):
        """获取规则"""
        rules = InfoCollectionRule.objects.filter(
            module=module,
            scan_type=scan_type,
            is_enabled=True
        )

        result = []
        for rule in rules:
            # 解析匹配值（按行分割）
            match_values = [v.strip() for v in rule.match_values.splitlines() if v.strip()]

            # 解析行为（按行分割）
            behaviors = []
            if rule.behaviors:
                behaviors = [b.strip() for b in rule.behaviors.splitlines() if b.strip()]

            result.append({
                'id': rule.id,
                'description': rule.description,
                'rule_type': rule.rule_type,
                'match_values': match_values,
                'behaviors': behaviors
            })

        return result

    @sync_to_async
    def save_scan_result(self, asset, module, scan_type, description, rule_type, match_value, behavior):
        """保存扫描结果"""
        # 检查是否已存在相同的结果
        existing_results = ScanResult.objects.filter(
            asset=asset,
            module=module,
            description=description,
            rule_type=rule_type,
            match_value=match_value
        )

        # 如果是主动扫描并指定了行为，还需要匹配行为
        if scan_type == 'active' and behavior:
            existing_results = existing_results.filter(behavior=behavior)

        # 如果不存在相同的结果，才创建新记录
        if not existing_results.exists():
            ScanResult.objects.create(
                asset=asset,
                module=module,
                scan_type=scan_type,
                description=description,
                rule_type=rule_type,
                match_value=match_value,
                behavior=behavior,
                scan_date=timezone.now()
            )