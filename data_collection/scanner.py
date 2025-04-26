import asyncio
import json
from urllib.parse import urlparse, urljoin
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
        self.scan_timeout = 10  # 默认扫描超时时间（秒）
        self.max_concurrent_scans = 5  # 默认最大并发扫描数
        self.skip_targets = set()  # 要跳过的目标集合
        self.semaphore = asyncio.Semaphore(5)  # 默认并发数控制

        # 初始化各个扫描模块
        self.network_scanner = NetworkInfoScanner()
        self.os_scanner = OSInfoScanner()
        self.component_scanner = ComponentInfoScanner()

        # 添加已扫描资产跟踪
        self.scanned_assets = set()  # 记录已扫描资产ID

    # 添加重置扫描状态的方法
    def reset_scan_state(self):
        """重置扫描状态，清除缓存"""
        self.scanned_assets.clear()  # 清除资产记录
        self.network_scanner.clear_cache() if hasattr(self.network_scanner, 'clear_cache') else None
        print("扫描状态已重置")

    def get_status_text(self, status_code):
        """获取HTTP状态码对应的文本描述"""
        status_dict = {
            200: "OK",
            201: "Created",
            202: "Accepted",
            204: "No Content",
            301: "Moved Permanently",
            302: "Found",
            303: "See Other",
            304: "Not Modified",
            307: "Temporary Redirect",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            408: "Request Timeout",
            500: "Internal Server Error",
            501: "Not Implemented",
            502: "Bad Gateway",
            503: "Service Unavailable",
            504: "Gateway Timeout",
        }
        return status_dict.get(status_code, "Unknown")

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

        # 检查是否已经处理过该资产的端口扫描
        asset_key = f"{asset_id}-port-scan"
        if asset_key in self.scanned_assets:
            # 如果已处理过，只进行非端口扫描的检查
            print(f"跳过资产{asset_id}的重复端口扫描")
        else:
            # 标记该资产已处理端口扫描
            self.scanned_assets.add(asset_key)

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
        method = context['method']
        status_code = context['status_code']
        req_headers = context['req_headers']
        req_content = context['req_content']
        resp_headers = context['resp_headers']
        resp_content = context['resp_content']
        channel_layer = context['channel_layer']

        # 格式化请求和响应数据，用于保存
        request_data = f"{method} {url}\n"
        for header, value in req_headers.items():
            request_data += f"{header}: {value}\n"
        request_data += f"\n{req_content}"

        response_data = f"HTTP/1.1 {status_code} {self.get_status_text(status_code)}\n"
        for header, value in resp_headers.items():
            response_data += f"{header}: {value}\n"
        response_data += f"\n{resp_content}"

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
                # 只保存匹配到的值，避免保存所有匹配值
                match_value = '\n'.join(match_results)

                # 检查是否已存在相同的结果，避免重复添加
                existing = await self.check_existing_result(
                    asset=asset,
                    module='network',
                    description=description,
                    rule_type=rule_type,
                    match_value=match_value
                )

                if not existing:
                    # 保存新的扫描结果，并保存完整的请求和响应数据
                    await self.save_scan_result(
                        asset=asset,
                        module='network',
                        scan_type='passive',
                        description=description,
                        rule_type=rule_type,
                        match_value=match_value,
                        behavior=None,
                        request_data=request_data,
                        response_data=response_data
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
                                'match_value': match_value,
                                'behavior': None,
                                'request_data': request_data,
                                'response_data': response_data,
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
            rule_type = rule['rule_type']
            match_values = rule['match_values']
            behaviors = rule['behaviors']

            # 对端口扫描规则的特殊处理
            if rule_type == 'port':
                try:
                    # 解析URL获取主机名
                    parsed_url = urlparse(url)
                    host = parsed_url.netloc

                    # 处理带端口号的主机名
                    if ':' in host:
                        host = host.split(':')[0]

                    # 设置超时
                    scan_result = await asyncio.wait_for(
                        self.network_scanner.scan(
                            url=url,
                            behavior='',  # 端口扫描不需要行为
                            rule_type='port',
                            match_values=match_values,
                            use_proxy=self.use_proxy,
                            proxy_address=self.proxy_address
                        ),
                        timeout=self.scan_timeout
                    )

                    # 如果有匹配结果，保存扫描结果
                    if scan_result:
                        match_value = scan_result.get('match_value', '')

                        # 构建端口扫描的请求和响应数据
                        port_request_data = f"PORT SCAN {host}\nPorts: {', '.join(match_values)}"
                        port_response_data = f"Open ports: {match_value}"

                        # 检查是否已存在相同的结果
                        existing = await self.check_existing_result(
                            asset=asset,
                            module='network',
                            description=description,
                            rule_type=rule_type,
                            match_value=match_value
                        )

                        if not existing:
                            await self.save_scan_result(
                                asset=asset,
                                module='network',
                                scan_type='active',
                                description=description,
                                rule_type=rule_type,
                                match_value=match_value,
                                behavior=None,
                                request_data=port_request_data,
                                response_data=port_response_data
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
                                        'behavior': None,
                                        'request_data': port_request_data,
                                        'response_data': port_response_data,
                                        'scan_date': timezone.now().isoformat()
                                    }
                                }
                            )

                except asyncio.TimeoutError:
                    # 扫描超时，跳过
                    continue
                except Exception as e:
                    # 扫描出错，跳过
                    print(f"端口扫描出错: {str(e)}")
                    continue

                # 端口扫描规则处理完毕，继续下一个规则
                continue

            # 其他类型的主动扫描规则
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

                        # 构建主动扫描的请求和响应数据
                        active_url = urljoin(url, behavior)
                        active_request_data = f"GET {active_url}\nHost: {parsed_url.netloc}\nUser-Agent: Mozilla/5.0...\nAccept: */*"
                        active_response_data = f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<active scan result containing: {match_value}>"

                        # 检查是否已存在相同的结果
                        existing = await self.check_existing_result(
                            asset=asset,
                            module='network',
                            description=description,
                            rule_type=rule_type,
                            match_value=match_value
                        )

                        if not existing:
                            await self.save_scan_result(
                                asset=asset,
                                module='network',
                                scan_type='active',
                                description=description,
                                rule_type=rule_type,
                                match_value=match_value,
                                behavior=behavior,
                                request_data=active_request_data,
                                response_data=active_response_data
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
                                        'request_data': active_request_data,
                                        'response_data': active_response_data,
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
        method = context['method']
        status_code = context['status_code']
        req_headers = context['req_headers']
        req_content = context['req_content']
        resp_headers = context['resp_headers']
        resp_content = context['resp_content']
        channel_layer = context['channel_layer']

        # 格式化请求和响应数据，用于保存
        request_data = f"{method} {url}\n"
        for header, value in req_headers.items():
            request_data += f"{header}: {value}\n"
        request_data += f"\n{req_content}"

        response_data = f"HTTP/1.1 {status_code} {self.get_status_text(status_code)}\n"
        for header, value in resp_headers.items():
            response_data += f"{header}: {value}\n"
        response_data += f"\n{resp_content}"

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
                # 只保存匹配到的值，避免保存所有匹配值
                match_value = '\n'.join(match_results)

                # 检查是否已存在相同的结果，避免重复添加
                existing = await self.check_existing_result(
                    asset=asset,
                    module='os',
                    description=description,
                    rule_type=rule_type,
                    match_value=match_value
                )

                if not existing:
                    # 保存新的扫描结果
                    await self.save_scan_result(
                        asset=asset,
                        module='os',
                        scan_type='passive',
                        description=description,
                        rule_type=rule_type,
                        match_value=match_value,
                        behavior=None,
                        request_data=request_data,
                        response_data=response_data
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
                                'match_value': match_value,
                                'behavior': None,
                                'request_data': request_data,
                                'response_data': response_data,
                                'scan_date': timezone.now().isoformat()
                            }
                        }
                    )

        # 省略主动扫描部分，处理方式与scan_network_info类似...

    async def scan_component_info(self, context):
        """
        扫描组件与服务信息

        参数:
            context: 扫描上下文
        """
        # 获取上下文数据
        asset = context['asset']
        url = context['url']
        method = context['method']
        status_code = context['status_code']
        req_headers = context['req_headers']
        req_content = context['req_content']
        resp_headers = context['resp_headers']
        resp_content = context['resp_content']
        channel_layer = context['channel_layer']

        # 格式化请求和响应数据，用于保存
        request_data = f"{method} {url}\n"
        for header, value in req_headers.items():
            request_data += f"{header}: {value}\n"
        request_data += f"\n{req_content}"

        response_data = f"HTTP/1.1 {status_code} {self.get_status_text(status_code)}\n"
        for header, value in resp_headers.items():
            response_data += f"{header}: {value}\n"
        response_data += f"\n{resp_content}"

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
                # 只保存匹配到的值，避免保存所有匹配值
                match_value = '\n'.join(match_results)

                # 检查是否已存在相同的结果，避免重复添加
                existing = await self.check_existing_result(
                    asset=asset,
                    module='component',
                    description=description,
                    rule_type=rule_type,
                    match_value=match_value
                )

                if not existing:
                    # 保存新的扫描结果
                    await self.save_scan_result(
                        asset=asset,
                        module='component',
                        scan_type='passive',
                        description=description,
                        rule_type=rule_type,
                        match_value=match_value,
                        behavior=None,
                        request_data=request_data,
                        response_data=response_data
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
                                'match_value': match_value,
                                'behavior': None,
                                'request_data': request_data,
                                'response_data': response_data,
                                'scan_date': timezone.now().isoformat()
                            }
                        }
                    )

        # 省略主动扫描部分，处理方式与scan_network_info类似...

    # 辅助方法

    @sync_to_async
    def get_asset(self, asset_id):
        """获取资产"""
        return Asset.objects.get(id=asset_id)

    @sync_to_async
    def check_existing_result(self, asset, module, description, rule_type, match_value):
        """检查是否已存在相同的扫描结果"""
        return ScanResult.objects.filter(
            asset=asset,
            module=module,
            description=description,
            rule_type=rule_type,
            match_value=match_value
        ).exists()

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
    def save_scan_result(self, asset, module, scan_type, description, rule_type, match_value, behavior, request_data,
                         response_data):
        """保存扫描结果"""
        try:
            # 创建扫描结果，同时保存请求和响应数据
            scan_result = ScanResult.objects.create(
                asset=asset,
                module=module,
                scan_type=scan_type,
                description=description,
                rule_type=rule_type,
                match_value=match_value,
                behavior=behavior,
                request_data=request_data,
                response_data=response_data,
                scan_date=timezone.now()
            )
            return scan_result
        except Exception as e:
            # 如果保存失败（例如唯一约束冲突），则忽略错误
            print(f"保存扫描结果失败: {str(e)}")
            return None