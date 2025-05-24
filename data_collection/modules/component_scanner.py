"""
组件信息扫描模块：负责扫描网站组件和服务相关信息
"""
import asyncio
import json
import aiohttp
from urllib.parse import urlparse, urljoin


class ComponentScanner:
    """组件信息扫描模块类"""

    def __init__(self):
        """初始化扫描器"""
        # 添加结果缓存，避免重复发送相同结果
        # 格式: (asset_id, module, rule_type, description)
        self.result_cache = set()

        # 添加组件特征签名缓存
        self.signatures_cache = None

    def clear_cache(self):
        """清除缓存"""
        self.result_cache.clear()
        self.signatures_cache = None
        print("组件扫描器缓存已清除")

    async def scan(self, context):
        """
        扫描组件信息

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

        # 获取全局扫描器实例的方法用于检查和添加全局缓存
        scanner = context.get('scanner')

        # 格式化请求和响应数据，用于保存
        request_data = helpers.format_request_data(method, url, req_headers, req_content)
        response_data = helpers.format_response_data(status_code, resp_headers, resp_content)

        # 获取被动扫描规则
        passive_rules = await helpers.get_rules('component', 'passive')
        print(f"获取到 {len(passive_rules)} 条组件模块被动扫描规则")

        # 进行被动扫描
        await self._do_passive_scan(
            passive_rules=passive_rules,
            context=context,
            request_data=request_data,
            response_data=response_data,
            helpers=helpers,
            scanner=scanner
        )

        # 使用组件信息扫描器进行主动扫描
        active_rules = await helpers.get_rules('component', 'active')
        print(f"获取到 {len(active_rules)} 条组件模块主动扫描规则")

        # 如果没有规则，跳过主动扫描
        if not active_rules:
            print("没有组件模块主动扫描规则，跳过主动扫描")
            return

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
        use_proxy = context['use_proxy']
        proxy_address = context['proxy_address']

        # 加载组件特征签名
        if self.signatures_cache is None:
            self.signatures_cache = await self._load_component_signatures(context)

        # 预处理请求和响应头，确保所有值都是字符串
        processed_req_headers = {}
        processed_resp_headers = {}

        # 预处理请求头
        for key, value in req_headers.items():
            try:
                # 确保键是字符串
                if isinstance(key, bytes):
                    key = key.decode('utf-8', errors='replace')
                elif not isinstance(key, str):
                    key = str(key)

                # 确保值是字符串
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='replace')
                    except UnicodeDecodeError:
                        value = "[二进制数据]"
                elif not isinstance(value, str):
                    value = str(value)

                processed_req_headers[key] = value
            except Exception as e:
                print(f"处理请求头时出错: {str(e)}")
                # 跳过无法处理的头部
                continue

        # 预处理响应头
        for key, value in resp_headers.items():
            try:
                # 确保键是字符串
                if isinstance(key, bytes):
                    key = key.decode('utf-8', errors='replace')
                elif not isinstance(key, str):
                    key = str(key)

                # 确保值是字符串
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='replace')
                    except UnicodeDecodeError:
                        value = "[二进制数据]"
                elif not isinstance(value, str):
                    value = str(value)

                processed_resp_headers[key] = value
            except Exception as e:
                print(f"处理响应头时出错: {str(e)}")
                # 跳过无法处理的头部
                continue

        # 自动检测组件
        if self.signatures_cache:
            # 使用加载的特征签名进行组件检测
            detected_components = await self.detect_components(
                url=url,
                resp_headers=processed_resp_headers,
                resp_content=resp_content,
                use_proxy=use_proxy,
                proxy_address=proxy_address,
                signatures=self.signatures_cache
            )

            # 如果检测到组件，保存结果
            if detected_components:
                for component in detected_components:
                    # 创建缓存键
                    cache_key = (asset.id, 'component', 'auto_detect', component)

                    # 检查全局缓存和模块缓存
                    if (scanner and hasattr(scanner, 'is_result_in_cache') and
                        scanner.is_result_in_cache(asset.id, 'component', component, 'auto_detect', '')):
                        print(f"跳过全局缓存中已存在的组件检测结果: {component}")
                        continue

                    if cache_key in self.result_cache:
                        print(f"跳过模块缓存中已存在的组件检测结果: {component}")
                        continue

                    # 添加到模块缓存
                    self.result_cache.add(cache_key)

                    # 添加到全局缓存
                    if scanner and hasattr(scanner, 'add_result_to_cache'):
                        scanner.add_result_to_cache(asset.id, 'component', component, 'auto_detect', component)

                    # 检查是否已存在相同的结果
                    existing = await helpers.check_existing_result(
                        asset=asset,
                        module='component',
                        description=f"检测到组件: {component}",
                        rule_type='auto_detect',
                        match_value=component
                    )

                    if not existing:
                        # 保存检测结果
                        scan_result = await helpers.save_scan_result(
                            asset=asset,
                            module='component',
                            scan_type='passive',
                            description=f"检测到组件: {component}",
                            rule_type='auto_detect',
                            match_value=component,
                            behavior=None,
                            request_data=request_data,
                            response_data=response_data
                        )

                        # 发送扫描结果事件 - 使用主机名代替ID
                        if scan_result:
                            await channel_layer.group_send(
                                'data_collection_scanner',
                                {
                                    'type': 'scan_result',
                                    'data': {
                                        'id': scan_result.id,
                                        'asset': asset.host,  # 使用主机名而不是ID
                                        'asset_host': asset.host,  # 添加资产主机名
                                        'module': 'component',
                                        'module_display': '组件与服务信息',
                                        'scan_type': 'passive',
                                        'scan_type_display': '被动扫描',
                                        'description': f"检测到组件: {component}",
                                        'rule_type': 'auto_detect',
                                        'match_value': component,
                                        'behavior': None,
                                        'request_data': request_data,
                                        'response_data': response_data,
                                        'scan_date': None  # 由Django生成
                                    }
                                }
                            )

        # 手动规则扫描
        for rule in passive_rules:
            # 获取规则详情
            rule_id = rule['id']
            description = rule['description']
            rule_type = rule['rule_type']
            match_values = rule['match_values']

            # 创建缓存键
            cache_key = (asset.id, 'component', rule_type, description)

            # 检查全局缓存
            if scanner and hasattr(scanner, 'is_result_in_cache') and scanner.is_result_in_cache(asset.id, 'component',
                                                                                                 description, rule_type,
                                                                                                 ''):
                print(f"跳过全局缓存中已存在的组件结果: {cache_key}")
                continue

            # 检查模块级缓存
            if cache_key in self.result_cache:
                print(f"跳过模块缓存中已存在的组件结果: {cache_key}")
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
                # HTTP头匹配 - 使用预处理后的头部
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
                            continue

                        # 安全获取头部值 - 使用预处理后的头部
                        if is_valid_header_value:
                            # 检查请求头
                            if header_name in processed_req_headers:
                                req_header_value = processed_req_headers[header_name]

                                # 跳过标记为二进制数据的值
                                if req_header_value == "[二进制数据]":
                                    continue

                                if not header_value or header_value.lower() in req_header_value.lower():
                                    match_results.append(match_value)
                                    continue

                            # 检查响应头
                            if header_name in processed_resp_headers:
                                resp_header_value = processed_resp_headers[header_name]

                                # 跳过标记为二进制数据的值
                                if resp_header_value == "[二进制数据]":
                                    continue

                                if not header_value or header_value.lower() in resp_header_value.lower():
                                    match_results.append(match_value)
                                    continue
                    except Exception as e:
                        print(f"处理HTTP头匹配值时出错: {str(e)}")
                        import traceback
                        traceback.print_exc()
                        continue

            # 如果有匹配结果，保存扫描结果
            if match_results:
                # 只保存匹配到的值，避免保存所有匹配值
                match_value = '\n'.join(match_results)

                # 检查是否已存在相同的结果，避免重复添加
                existing = await helpers.check_existing_result(
                    asset=asset,
                    module='component',
                    description=description,
                    rule_type=rule_type,
                    match_value=match_value
                )

                # 添加到模块级缓存
                self.result_cache.add(cache_key)

                # 添加到全局缓存
                if scanner and hasattr(scanner, 'add_result_to_cache'):
                    scanner.add_result_to_cache(asset.id, 'component', description, rule_type, match_value)

                if not existing:
                    # 保存新的扫描结果
                    scan_result = await helpers.save_scan_result(
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

                    print(f"保存组件被动扫描结果: 资产={asset.host}, 描述={description}")

                    # 发送扫描结果事件 - 使用主机名代替ID
                    await channel_layer.group_send(
                        'data_collection_scanner',
                        {
                            'type': 'scan_result',
                            'data': {
                                'id': scan_result.id if scan_result else None,
                                'asset': asset.host,  # 使用主机名而不是ID
                                'asset_host': asset.host,  # 添加资产主机名
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
                                'scan_date': None  # 由Django生成
                            }
                        }
                    )
                else:
                    print(f"跳过重复的组件被动扫描结果: 资产={asset.host}, 描述={description}")

    async def _do_active_scan(self, active_rules, context, helpers, scanner=None):
        """执行主动扫描"""
        asset = context['asset']
        url = context['url']
        channel_layer = context['channel_layer']
        use_proxy = context['use_proxy']
        proxy_address = context['proxy_address']
        scan_timeout = context['scan_timeout']

        # 遍历主动扫描规则
        for rule in active_rules:
            rule_id = rule['id']
            description = rule['description']
            rule_type = rule['rule_type']
            match_values = rule['match_values']
            behaviors = rule['behaviors']

            # 创建规则缓存键
            cache_key = (asset.id, 'component', rule_type, description)

            # 检查全局缓存
            if scanner and hasattr(scanner, 'is_result_in_cache') and scanner.is_result_in_cache(asset.id, 'component',
                                                                                                 description, rule_type,
                                                                                                 ''):
                print(f"跳过全局缓存中已存在的组件主动扫描结果: {cache_key}")
                continue

            # 检查模块级缓存 - 基本规则检查
            if cache_key in self.result_cache:
                print(f"跳过模块缓存中已存在的组件主动扫描结果: {cache_key}")
                continue

            if not behaviors:
                print(f"组件规则 {rule_id} ({description}) 没有行为定义，跳过")
                continue

            print(f"准备对资产 {asset.host} 执行组件主动扫描规则 {rule_id} ({description})")
            print(f"行为列表: {behaviors}")

            # 执行每个行为
            for behavior in behaviors:
                try:
                    # 创建行为特定的缓存键
                    behavior_cache_key = (asset.id, 'component', rule_type, description, behavior)

                    # 检查行为特定的缓存
                    if behavior_cache_key in self.result_cache:
                        print(f"跳过已缓存的组件行为: {behavior}")
                        continue

                    print(f"执行组件主动扫描: 行为={behavior}")

                    # 设置超时
                    scan_result = await asyncio.wait_for(
                        self.scan_url(
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
                        print(f"组件主动扫描有匹配结果: {match_value}")

                        # 构建主动扫描的请求和响应数据
                        parsed_url = urlparse(url)
                        active_url = urljoin(url, behavior)
                        active_request_data = f"GET {active_url}\nHost: {parsed_url.netloc}\nUser-Agent: Mozilla/5.0 (Safe Version)...\nAccept: */*"
                        active_response_data = f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<component active scan result containing: {match_value}>"

                        # 检查是否已存在相同的结果
                        existing = await helpers.check_existing_result(
                            asset=asset,
                            module='component',
                            description=description,
                            rule_type=rule_type,
                            match_value=match_value
                        )

                        # 添加到模块级缓存 - 同时缓存基本规则和行为
                        self.result_cache.add(cache_key)
                        self.result_cache.add(behavior_cache_key)

                        # 添加到全局缓存
                        if scanner and hasattr(scanner, 'add_result_to_cache'):
                            scanner.add_result_to_cache(asset.id, 'component', description, rule_type, match_value)

                        if not existing:
                            scan_result = await helpers.save_scan_result(
                                asset=asset,
                                module='component',
                                scan_type='active',
                                description=description,
                                rule_type=rule_type,
                                match_value=match_value,
                                behavior=behavior,
                                request_data=active_request_data,
                                response_data=active_response_data
                            )

                            print(f"保存组件主动扫描结果: 资产={asset.host}, 描述={description}, 行为={behavior}")

                            # 发送扫描结果事件 - 使用主机名代替ID
                            await channel_layer.group_send(
                                'data_collection_scanner',
                                {
                                    'type': 'scan_result',
                                    'data': {
                                        'id': scan_result.id if scan_result else None,
                                        'asset': asset.host,  # 使用主机名而不是ID
                                        'asset_host': asset.host,  # 添加资产主机名
                                        'module': 'component',
                                        'module_display': '组件与服务信息',
                                        'scan_type': 'active',
                                        'scan_type_display': '主动扫描',
                                        'description': description,
                                        'rule_type': rule_type,
                                        'match_value': match_value,
                                        'behavior': behavior,
                                        'request_data': active_request_data,
                                        'response_data': active_response_data,
                                        'scan_date': None  # 由Django生成
                                    }
                                }
                            )
                        else:
                            print(f"跳过重复的组件主动扫描结果: 资产={asset.host}, 描述={description}, 行为={behavior}")
                    else:
                        print(f"组件行为 {behavior} 没有匹配结果")

                except asyncio.TimeoutError:
                    print(f"组件主动扫描行为 {behavior} 超时")
                    continue
                except Exception as e:
                    print(f"组件主动扫描行为 {behavior} 出错: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    continue

    async def scan_url(self, url, behavior, rule_type, match_values, use_proxy=False, proxy_address=None):
        """
        根据规则扫描组件与服务信息

        参数:
            url: 目标URL
            behavior: 扫描行为
            rule_type: 规则类型 (status_code, response_content, header)
            match_values: 匹配值列表
            use_proxy: 是否使用代理
            proxy_address: 代理地址

        返回:
            匹配结果字典，如果没有匹配则返回None
        """
        # 日志记录和参数验证
        print(f"组件扫描参数: URL={url}, 行为={behavior}, 规则类型={rule_type}")
        if not match_values or len(match_values) == 0:
            print(f"警告: 没有提供匹配值，跳过组件扫描")
            return None

        # 解析原始URL，获取基本域名和协议
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # 构建目标URL（基本URL + 行为路径）
        target_url = urljoin(base_url, behavior)

        # 设置代理
        proxy = None
        if use_proxy and proxy_address:
            proxy = proxy_address

        # 构建请求头
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'close',
        }

        try:
            # 创建异步HTTP会话
            async with aiohttp.ClientSession() as session:
                # 发送请求
                async with session.get(
                        target_url,
                        headers=headers,
                        proxy=proxy,
                        ssl=False,  # 忽略SSL证书验证
                        timeout=aiohttp.ClientTimeout(total=10)  # 设置超时
                ) as response:
                    # 获取响应状态码
                    status_code = response.status

                    # 获取响应头 - 使用安全解码
                    resp_headers = {}
                    for key, value in response.headers.items():
                        safe_key = self.safe_decode(key)
                        safe_value = self.safe_decode(value)

                        # 跳过解码失败的头部
                        if "[解码失败" in safe_key or "[二进制数据" in safe_key:
                            continue
                        if "[解码失败" in safe_value or "[二进制数据" in safe_value:
                            safe_value = "[二进制内容]"

                        resp_headers[safe_key] = safe_value

                    # 获取响应内容
                    resp_content = await response.text(errors='replace')

                    # 根据规则类型进行匹配
                    if rule_type == 'status_code':
                        # 状态码判断
                        if str(status_code) in match_values:
                            return {'match_value': str(status_code)}

                    elif rule_type == 'response_content':
                        # 响应内容匹配
                        for match_value in match_values:
                            if match_value.lower() in resp_content.lower():
                                return {'match_value': match_value}

                    elif rule_type == 'header':
                        # HTTP头匹配 - 添加更多的安全检查
                        for match_value in match_values:
                            try:
                                # 安全解析匹配值
                                if ':' in match_value:
                                    header_parts = match_value.split(':', 1)
                                    header_name = header_parts[0].strip()
                                    header_value = header_parts[1].strip() if len(header_parts) > 1 else ''
                                else:
                                    header_name = match_value.strip()
                                    header_value = ''

                                # 检查头名称是否有效
                                if not header_name or header_name in ["[编码错误]", "[二进制数据", "[解码失败"]:
                                    print(f"无效的HTTP头名称: {header_name}")
                                    continue

                                # 检查头是否存在
                                if header_name in resp_headers:
                                    actual_value = resp_headers[header_name]

                                    # 跳过二进制内容
                                    if actual_value == "[二进制内容]":
                                        continue

                                    # 如果没有指定值，或者值包含在实际值中
                                    if not header_value or (header_value.lower() in actual_value.lower()):
                                        return {'match_value': match_value}
                            except Exception as e:
                                print(f"处理HTTP头匹配值时出错: {str(e)}")
                                continue

            # 没有匹配结果
            return None

        except aiohttp.ClientConnectorError as e:
            # 连接错误，可能是端口关闭
            print(f"连接错误: {str(e)}")
            return None
        except aiohttp.ClientError as e:
            # 其他HTTP客户端错误
            print(f"HTTP客户端错误: {str(e)}")
            return None
        except asyncio.TimeoutError:
            # 请求超时
            print(f"请求超时")
            return None
        except Exception as e:
            # 其他错误
            print(f"组件与服务信息扫描出错: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    async def detect_components(self, url, resp_headers, resp_content, use_proxy=False, proxy_address=None, signatures=None):
        """
        检测网站使用的组件和服务

        参数:
            url: 目标URL
            resp_headers: 响应头
            resp_content: 响应内容
            use_proxy: 是否使用代理
            proxy_address: 代理地址
            signatures: 组件特征签名，如果为None则使用默认配置

        返回:
            检测到的组件列表
        """
        # 如果没有提供特征签名，则返回空列表
        if not signatures:
            print("警告: 没有提供组件特征签名")
            return []

        # 解析原始URL
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # 设置代理
        proxy = None
        if use_proxy and proxy_address:
            proxy = proxy_address

        detected_components = []

        try:
            # 检查每个组件的特征指纹
            for component, component_signatures in signatures.items():
                for signature in component_signatures:
                    try:
                        # 验证签名格式
                        if not isinstance(signature, dict) or 'type' not in signature:
                            print(f"无效的特征签名格式: {signature}")
                            continue

                        sig_type = signature.get('type')

                        if sig_type == 'header':
                            # 检查HTTP头
                            header_name = signature.get('name')
                            header_value = signature.get('value', '')

                            if not header_name:
                                print(f"无效的HTTP头名称: {header_name}")
                                continue

                            # 检查头名称是否有效
                            if header_name in ["[编码错误]", "[二进制数据", "[解码失败"]:
                                continue

                            # 安全检查头部
                            if header_name in resp_headers:
                                actual_value = resp_headers[header_name]

                                # 跳过二进制内容
                                if actual_value == "[二进制内容]":
                                    continue

                                if not header_value or header_value.lower() in actual_value.lower():
                                    if component not in detected_components:
                                        detected_components.append(component)
                                        print(f"通过HTTP头 {header_name} 检测到组件: {component}")

                        elif sig_type == 'content':
                            # 检查响应内容
                            content_value = signature.get('value')

                            if not content_value:
                                continue

                            if content_value.lower() in resp_content.lower():
                                if component not in detected_components:
                                    detected_components.append(component)
                                    print(f"通过内容匹配 '{content_value}' 检测到组件: {component}")
                    except Exception as e:
                        print(f"处理组件特征时出错: {str(e)}")
                        continue

            # 请求特定路径
            async with aiohttp.ClientSession() as session:
                for component, component_signatures in signatures.items():
                    for signature in component_signatures:
                        try:
                            if signature.get('type') == 'path':
                                path_value = signature.get('value')
                                if not path_value:
                                    continue

                                path_url = urljoin(base_url, path_value)

                                try:
                                    async with session.get(
                                            path_url,
                                            proxy=proxy,
                                            ssl=False,
                                            timeout=aiohttp.ClientTimeout(total=5)
                                    ) as path_response:
                                        # 如果请求成功（状态码200），则认为检测到了组件
                                        if path_response.status == 200:
                                            if component not in detected_components:
                                                detected_components.append(component)
                                                print(f"通过路径 {path_value} 检测到组件: {component}")

                                except Exception as path_error:
                                    # 忽略路径请求错误
                                    continue
                        except Exception as e:
                            print(f"处理路径特征时出错: {str(e)}")
                            continue

        except Exception as e:
            # 扫描出错
            print(f"组件检测出错: {str(e)}")
            import traceback
            traceback.print_exc()

        return detected_components

    async def _load_component_signatures(self, context):
        """
        加载组件特征签名

        参数:
            context: 扫描上下文

        返回:
            加载的特征签名字典
        """
        try:
            # 从上下文中获取帮助类
            helpers = context.get('helpers')
            if not helpers:
                print("缺少辅助类，无法加载组件特征签名")
                return {}

            # 从数据库获取规则
            rules = await helpers.get_rules('component', 'passive')

            # 查找名为"组件特征签名"的规则
            signature_rule = None
            for rule in rules:
                if '组件特征签名' in rule.get('description', ''):
                    signature_rule = rule
                    break

            if not signature_rule:
                print("未找到组件特征签名规则")
                return {}

            # 解析规则内容
            try:
                # 使用match_values字段中的内容作为JSON字符串
                match_values = signature_rule.get('match_values', [])
                if isinstance(match_values, list) and len(match_values) > 0:
                    signatures_str = match_values[0]
                    signatures = json.loads(signatures_str)
                    print(f"成功加载组件特征签名: {len(signatures)} 个组件")
                    return signatures
                else:
                    print("组件特征签名规则格式错误，match_values为空")
                    return {}
            except json.JSONDecodeError:
                print(f"组件特征签名格式错误，无法解析JSON")
                return {}
            except Exception as e:
                print(f"解析组件特征签名时出错: {str(e)}")
                return {}

        except Exception as e:
            print(f"加载组件特征签名失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return {}

    def safe_decode(self, value):
        """
        安全地解码任何值，处理所有可能的编码错误
        增强处理二进制数据的能力
        """
        if value is None:
            return ""

        if isinstance(value, bytes):
            try:
                # 首先尝试UTF-8解码
                return value.decode('utf-8', errors='replace')
            except Exception:
                # 尝试其他编码
                for encoding in ['latin1', 'cp1252', 'iso-8859-1', 'gbk', 'gb2312']:
                    try:
                        return value.decode(encoding, errors='replace')
                    except:
                        continue

                # 如果所有解码都失败，转为十六进制表示
                try:
                    return f"[二进制数据: {value[:20].hex()}...]"
                except:
                    return "[二进制数据]"

        if isinstance(value, str):
            # 如果已经是字符串，确保它是有效的UTF-8
            try:
                valid_str = value.encode('utf-8', errors='replace').decode('utf-8')
                return valid_str
            except Exception:
                return value.replace('\ufffd', '?')  # 替换替换字符为问号

        # 处理其他类型
        try:
            return str(value)
        except Exception:
            return "[无法转换为字符串的对象]"