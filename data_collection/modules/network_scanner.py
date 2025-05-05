"""
网络信息扫描模块：负责扫描网络相关信息
"""
import asyncio
from urllib.parse import urlparse, urljoin
from ..network_info import NetworkInfoScanner


class NetworkScanner:
    """网络信息扫描模块类"""

    def __init__(self):
        """初始化扫描器"""
        self.network_info_scanner = NetworkInfoScanner()
        self.port_scan_cache = set()  # 缓存已扫描的端口

        # 添加更强的结果缓存，避免重复发送相同结果
        # 格式: (asset_id, module, rule_type, description)
        self.result_cache = set()

    def clear_cache(self):
        """清除缓存"""
        self.port_scan_cache.clear()
        self.result_cache.clear()
        print("网络扫描器缓存已清除")

        # 如果 NetworkInfoScanner 也有缓存清理方法，同时清理
        if hasattr(self.network_info_scanner, 'clear_cache'):
            self.network_info_scanner.clear_cache()

    async def scan(self, context):
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
        helpers = context['helpers']
        use_proxy = context['use_proxy']
        proxy_address = context['proxy_address']
        scan_timeout = context['scan_timeout']

        # 重要：获取全局扫描器实例的方法用于检查和添加全局缓存
        scanner = context.get('scanner')

        # 格式化请求和响应数据，用于保存
        request_data = helpers.format_request_data(method, url, req_headers, req_content)
        response_data = helpers.format_response_data(status_code, resp_headers, resp_content)

        # 获取被动扫描规则
        passive_rules = await helpers.get_rules('network', 'passive')
        print(f"获取到 {len(passive_rules)} 条网络模块被动扫描规则")

        # 进行被动扫描
        await self._do_passive_scan(
            passive_rules=passive_rules,
            context=context,
            request_data=request_data,
            response_data=response_data,
            helpers=helpers,
            scanner=scanner
        )

        # 使用网络信息扫描器进行主动扫描
        active_rules = await helpers.get_rules('network', 'active')
        print(f"获取到 {len(active_rules)} 条网络模块主动扫描规则")

        # 打印规则详情用于调试
        for rule in active_rules:
            print(f"规则ID: {rule['id']}, 描述: {rule['description']}, 规则类型: {rule['rule_type']}")
            print(f"行为列表: {rule['behaviors']}")
            print(f"匹配值列表: {rule['match_values']}")
            print("-" * 50)

        # 进行主动扫描
        await self._do_active_scan(
            active_rules=active_rules,
            context=context,
            helpers=helpers,
            scanner=scanner
        )

    async def _do_passive_scan(self, passive_rules, context, request_data, response_data, helpers, scanner=None):
        """执行被动扫描，增加去重逻辑"""
        asset = context['asset']
        url = context['url']
        status_code = context['status_code']
        req_headers = context['req_headers']
        resp_headers = context['resp_headers']
        resp_content = context['resp_content']
        channel_layer = context['channel_layer']

        for rule in passive_rules:
            # 获取规则详情
            rule_id = rule['id']
            description = rule['description']
            rule_type = rule['rule_type']
            match_values = rule['match_values']

            # 创建缓存键
            cache_key = (asset.id, 'network', rule_type, description)

            # 检查全局缓存
            if scanner and hasattr(scanner, 'is_result_in_cache') and scanner.is_result_in_cache(asset.id, 'network',
                                                                                                 description, rule_type,
                                                                                                 ''):
                print(f"跳过全局缓存中已存在的结果: {cache_key}")
                continue

            # 检查模块级缓存
            if cache_key in self.result_cache:
                print(f"跳过模块缓存中已存在的结果: {cache_key}")
                continue

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
                # HTTP头匹配 - 增加安全检查
                for match_value in match_values:
                    try:
                        # 添加深度检查
                        is_valid_header_value = True

                        # 解析头部名称和值
                        if ':' in match_value:
                            header_parts = match_value.split(':', 1)
                            header_name = header_parts[0].strip()
                            header_value = header_parts[1].strip() if len(header_parts) > 1 else ''
                        else:
                            header_name = match_value.strip()
                            header_value = ''

                        # 检查头部名称是否有效
                        if not header_name:
                            is_valid_header_value = False

                        # 安全获取头部值
                        if is_valid_header_value:
                            # 检查请求头
                            req_header_value = None
                            if header_name in req_headers:
                                # 安全解码请求头值
                                if isinstance(req_headers[header_name], bytes):
                                    try:
                                        req_header_value = req_headers[header_name].decode('utf-8', errors='replace')
                                    except Exception as e:
                                        print(f"请求头 {header_name} 解码失败: {str(e)}")
                                        req_header_value = None
                                else:
                                    req_header_value = req_headers[header_name]

                                if req_header_value:
                                    if not header_value or header_value.lower() in req_header_value.lower():
                                        match_results.append(match_value)
                                        continue

                            # 检查响应头
                            resp_header_value = None
                            if header_name in resp_headers:
                                # 安全解码响应头值
                                if isinstance(resp_headers[header_name], bytes):
                                    try:
                                        resp_header_value = resp_headers[header_name].decode('utf-8', errors='replace')
                                    except Exception as e:
                                        print(f"响应头 {header_name} 解码失败: {str(e)}")
                                        resp_header_value = None
                                else:
                                    resp_header_value = resp_headers[header_name]

                                if resp_header_value:
                                    if not header_value or header_value.lower() in resp_header_value.lower():
                                        match_results.append(match_value)
                                        continue
                    except Exception as e:
                        print(f"处理HTTP头匹配值时出错: {str(e)}")
                        continue

            # 如果有匹配结果，保存扫描结果
            if match_results:
                # 只保存匹配到的值，避免保存所有匹配值
                match_value = '\n'.join(match_results)

                # 检查是否已存在相同的结果，避免重复添加
                existing = await helpers.check_existing_result(
                    asset=asset,
                    module='network',
                    description=description,
                    rule_type=rule_type,
                    match_value=match_value
                )

                # 添加到模块级缓存
                self.result_cache.add(cache_key)

                # 添加到全局缓存
                if scanner and hasattr(scanner, 'add_result_to_cache'):
                    scanner.add_result_to_cache(asset.id, 'network', description, rule_type, match_value)

                if not existing:
                    # 保存新的扫描结果，并保存完整的请求和响应数据
                    scan_result = await helpers.save_scan_result(
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

                    print(f"保存被动扫描结果: 资产={asset.host}, 描述={description}, 匹配值={match_value[:50]}...")

                    # 发送扫描结果事件
                    await channel_layer.group_send(
                        'data_collection_scanner',
                        {
                            'type': 'scan_result',
                            'data': {
                                'id': scan_result.id if scan_result else None,
                                'asset': asset.host,  # 使用主机名而不是ID
                                'asset_host': asset.host,  # 添加资产主机名
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
                                'scan_date': None  # 由Django生成
                            }
                        }
                    )
                else:
                    print(f"跳过重复的被动扫描结果: 资产={asset.host}, 描述={description}")

    async def _do_active_scan(self, active_rules, context, helpers, scanner=None):
        """执行主动扫描"""
        asset = context['asset']
        url = context['url']
        channel_layer = context['channel_layer']
        use_proxy = context['use_proxy']
        proxy_address = context['proxy_address']
        scan_timeout = context['scan_timeout']

        # 限制主动扫描的超时时间
        for rule in active_rules:
            rule_id = rule['id']
            description = rule['description']
            rule_type = rule['rule_type']
            match_values = rule['match_values']
            behaviors = rule['behaviors']

            # 创建缓存键
            cache_key = (asset.id, 'network', rule_type, description)

            # 检查全局缓存
            if scanner and hasattr(scanner, 'is_result_in_cache') and scanner.is_result_in_cache(asset.id, 'network',
                                                                                                 description, rule_type,
                                                                                                 ''):
                print(f"跳过全局缓存中已存在的主动扫描结果: {cache_key}")
                continue

            # 检查模块级缓存
            if cache_key in self.result_cache:
                print(f"跳过模块缓存中已存在的主动扫描结果: {cache_key}")
                continue

            # 对端口扫描规则的特殊处理
            if rule_type == 'port':
                try:
                    # 解析URL获取主机名
                    parsed_url = urlparse(url)
                    host = parsed_url.netloc

                    # 处理带端口号的主机名
                    if ':' in host:
                        host = host.split(':')[0]

                    print(f"准备对主机 {host} 进行端口扫描, 端口列表: {match_values}")

                    # 设置超时
                    scan_result = await asyncio.wait_for(
                        self.network_info_scanner.scan(
                            url=url,
                            behavior='',  # 端口扫描不需要行为
                            rule_type='port',
                            match_values=match_values,
                            use_proxy=use_proxy,
                            proxy_address=proxy_address
                        ),
                        timeout=scan_timeout
                    )

                    # 如果有匹配结果，保存扫描结果
                    if scan_result:
                        match_value = scan_result.get('match_value', '')
                        print(f"端口扫描有结果: {match_value}")

                        # 构建端口扫描的请求和响应数据
                        port_request_data = f"PORT SCAN {host}\nPorts: {', '.join(match_values)}"
                        port_response_data = f"Open ports: {match_value}"

                        # 检查是否已存在相同的结果
                        existing = await helpers.check_existing_result(
                            asset=asset,
                            module='network',
                            description=description,
                            rule_type=rule_type,
                            match_value=match_value
                        )

                        # 添加到模块级缓存
                        self.result_cache.add(cache_key)

                        # 添加到全局缓存
                        if scanner and hasattr(scanner, 'add_result_to_cache'):
                            scanner.add_result_to_cache(asset.id, 'network', description, rule_type, match_value)

                        if not existing:
                            scan_result = await helpers.save_scan_result(
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

                            print(f"保存端口扫描结果: 资产={asset.host}, 描述={description}, 匹配值={match_value}")

                            # 提取端口号
                            port_numbers = []
                            for line in match_value.split('\n'):
                                if ':' in line:
                                    port = line.split(':', 1)[0].strip()
                                    if port.isdigit():
                                        port_numbers.append(port)

                            # 用于展示的端口号字符串
                            port_display = ", ".join(port_numbers) if port_numbers else "未知端口"

                            # 发送扫描结果事件 - 修改asset为host字符串
                            await channel_layer.group_send(
                                'data_collection_scanner',
                                {
                                    'type': 'scan_result',
                                    'data': {
                                        'id': scan_result.id if scan_result else None,
                                        'asset': asset.host,  # 使用主机名而不是ID
                                        'asset_host': asset.host,  # 添加资产主机名
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
                                        'scan_date': None,  # 由Django生成
                                        'is_port_scan': True,  # 标记为端口扫描结果
                                        'port_numbers': port_numbers,
                                        'port_display': port_display
                                    }
                                }
                            )
                        else:
                            print(f"跳过重复的端口扫描结果: 资产={asset.host}, 描述={description}")

                except asyncio.TimeoutError:
                    print(f"端口扫描超时")
                    continue
                except Exception as e:
                    print(f"端口扫描出错: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    continue

                # 端口扫描规则处理完毕，继续下一个规则
                continue

            # 其他类型的主动扫描规则
            if not behaviors:
                print(f"规则 {rule_id} ({description}) 没有行为定义，跳过")
                continue

            print(f"准备对资产 {asset.host} 执行主动扫描规则 {rule_id} ({description})")
            print(f"行为列表: {behaviors}")

            for behavior in behaviors:
                try:
                    # 构建主动扫描URL
                    target_url = urljoin(url, behavior)
                    print(f"执行主动扫描: {target_url}, 行为: {behavior}")

                    # 设置超时
                    scan_result = await asyncio.wait_for(
                        self.network_info_scanner.scan(
                            url=url,
                            behavior=behavior,
                            rule_type=rule_type,
                            match_values=match_values,
                            use_proxy=use_proxy,
                            proxy_address=proxy_address
                        ),
                        timeout=scan_timeout
                    )

                    # 如果有匹配结果，保存扫描结果
                    if scan_result:
                        match_value = scan_result.get('match_value', '')
                        print(f"主动扫描有匹配结果: {match_value}")

                        # 构建主动扫描的请求和响应数据
                        parsed_url = urlparse(url)
                        active_url = urljoin(url, behavior)
                        active_request_data = f"GET {active_url}\nHost: {parsed_url.netloc}\nUser-Agent: Mozilla/5.0...\nAccept: */*"
                        active_response_data = f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<active scan result containing: {match_value}>"

                        # 创建行为特定的缓存键
                        behavior_cache_key = (asset.id, 'network', rule_type, description, behavior)

                        # 检查是否已存在相同的结果
                        existing = await helpers.check_existing_result(
                            asset=asset,
                            module='network',
                            description=description,
                            rule_type=rule_type,
                            match_value=match_value
                        )

                        # 添加到模块级缓存
                        self.result_cache.add(behavior_cache_key)

                        # 添加到全局缓存
                        if scanner and hasattr(scanner, 'add_result_to_cache'):
                            scanner.add_result_to_cache(asset.id, 'network', description, rule_type, match_value)

                        if not existing:
                            scan_result = await helpers.save_scan_result(
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

                            print(
                                f"保存主动扫描结果: 资产={asset.host}, 描述={description}, 行为={behavior}, 匹配值={match_value}")

                            # 发送扫描结果事件 - 修改asset为host字符串
                            await channel_layer.group_send(
                                'data_collection_scanner',
                                {
                                    'type': 'scan_result',
                                    'data': {
                                        'id': scan_result.id if scan_result else None,
                                        'asset': asset.host,  # 使用主机名而不是ID
                                        'asset_host': asset.host,  # 添加资产主机名
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
                                        'scan_date': None,  # 由Django生成
                                        'is_port_scan': False  # 标记为非端口扫描结果
                                    }
                                }
                            )
                        else:
                            print(f"跳过重复的主动扫描结果: 资产={asset.host}, 描述={description}, 行为={behavior}")
                    else:
                        print(f"行为 {behavior} 没有匹配结果")

                except asyncio.TimeoutError:
                    print(f"主动扫描行为 {behavior} 超时")
                    continue
                except Exception as e:
                    print(f"主动扫描行为 {behavior} 出错: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    continue