"""
操作系统信息扫描模块：负责扫描操作系统相关信息
重构版：模仿漏洞扫描模块架构，集成原有功能
"""
import asyncio
import aiohttp
from urllib.parse import urlparse, urljoin


class OSScanner:
    """操作系统信息扫描模块类"""

    def __init__(self):
        """初始化扫描器"""
        # 添加结果缓存，避免重复发送相同结果
        # 格式: (asset_id, module, rule_type, description)
        self.result_cache = set()

    def clear_cache(self):
        """清除缓存"""
        self.result_cache.clear()
        print("操作系统扫描器缓存已清除")

    async def scan(self, context):
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
        passive_rules = await helpers.get_rules('os', 'passive')
        print(f"获取到 {len(passive_rules)} 条操作系统模块被动扫描规则")

        # 进行被动扫描
        await self._do_passive_scan(
            passive_rules=passive_rules,
            context=context,
            request_data=request_data,
            response_data=response_data,
            helpers=helpers,
            scanner=scanner
        )

        # 使用操作系统信息扫描器进行主动扫描
        active_rules = await helpers.get_rules('os', 'active')
        print(f"获取到 {len(active_rules)} 条操作系统模块主动扫描规则")

        # 打印规则详情用于调试
        for rule in active_rules:
            print(f"OS规则ID: {rule['id']}, 描述: {rule['description']}, 规则类型: {rule['rule_type']}")
            print(f"OS行为列表: {rule['behaviors']}")
            print(f"OS匹配值列表: {rule['match_values']}")
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
            cache_key = (asset.id, 'os', rule_type, description)

            # 检查全局缓存
            if scanner and hasattr(scanner, 'is_result_in_cache') and scanner.is_result_in_cache(
                    asset.id, 'os', description, rule_type, ''):
                print(f"跳过全局缓存中已存在的OS结果: {cache_key}")
                continue

            # 检查模块级缓存
            if cache_key in self.result_cache:
                print(f"跳过模块缓存中已存在的OS结果: {cache_key}")
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
                # HTTP头匹配
                for match_value in match_values:
                    header_name, header_value = match_value.split(':', 1) if ':' in match_value else (match_value, '')
                    header_name = header_name.strip()
                    header_value = header_value.strip()

                    # 检查请求头
                    if header_name in req_headers:
                        if not header_value or header_value.lower() in str(req_headers[header_name]).lower():
                            match_results.append(match_value)

                    # 检查响应头
                    if header_name in resp_headers:
                        if not header_value or header_value.lower() in str(resp_headers[header_name]).lower():
                            match_results.append(match_value)

            # 如果有匹配结果，保存扫描结果
            if match_results:
                # 只保存匹配到的值，避免保存所有匹配值
                match_value = '\n'.join(match_results)

                # 检查是否已存在相同的结果，避免重复添加
                existing = await helpers.check_existing_result(
                    asset=asset,
                    module='os',
                    description=description,
                    rule_type=rule_type,
                    match_value=match_value
                )

                # 添加到模块级缓存
                self.result_cache.add(cache_key)

                # 添加到全局缓存
                if scanner and hasattr(scanner, 'add_result_to_cache'):
                    scanner.add_result_to_cache(asset.id, 'os', description, rule_type, match_value)

                if not existing:
                    # 保存新的扫描结果
                    scan_result = await helpers.save_scan_result(
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

                    print(f"保存OS被动扫描结果: 资产={asset.host}, 描述={description}")

                    # 发送扫描结果事件 - 修改结果发送格式，使用asset.host代替ID
                    await channel_layer.group_send(
                        'data_collection_scanner',
                        {
                            'type': 'scan_result',
                            'data': {
                                'id': scan_result.id if scan_result else None,
                                'asset': asset.host,  # 使用主机名而不是ID
                                'asset_host': asset.host,  # 添加资产主机名字段
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
                                'scan_date': None  # 由Django生成
                            }
                        }
                    )
                else:
                    print(f"跳过重复的OS被动扫描结果: 资产={asset.host}, 描述={description}")

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

            # 创建缓存键
            cache_key = (asset.id, 'os', rule_type, description)

            # 检查全局缓存
            if scanner and hasattr(scanner, 'is_result_in_cache') and scanner.is_result_in_cache(
                    asset.id, 'os', description, rule_type, ''):
                print(f"跳过全局缓存中已存在的OS主动扫描结果: {cache_key}")
                continue

            # 检查模块级缓存 - 基本规则检查
            if cache_key in self.result_cache:
                print(f"跳过模块缓存中已存在的OS主动扫描结果: {cache_key}")
                continue

            if not behaviors:
                print(f"OS规则 {rule_id} ({description}) 没有行为定义，跳过")
                continue

            print(f"准备对资产 {asset.host} 执行OS主动扫描规则 {rule_id} ({description})")
            print(f"行为列表: {behaviors}")

            # 执行每个行为
            for behavior in behaviors:
                try:
                    # 创建行为特定的缓存键
                    behavior_cache_key = (asset.id, 'os', rule_type, description, behavior)

                    # 检查行为特定的缓存
                    if behavior_cache_key in self.result_cache:
                        print(f"跳过已缓存的OS行为: {behavior}")
                        continue

                    print(f"执行OS主动扫描: 行为={behavior}")

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
                        print(f"OS主动扫描有匹配结果: {match_value}")

                        # 构建主动扫描的请求和响应数据
                        parsed_url = urlparse(url)
                        active_url = urljoin(url, behavior)
                        active_request_data = f"GET {active_url}\nHost: {parsed_url.netloc}\nUser-Agent: Mozilla/5.0 (Safe Version)...\nAccept: */*"
                        active_response_data = f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<os active scan result containing: {match_value}>"

                        # 检查是否已存在相同的结果
                        existing = await helpers.check_existing_result(
                            asset=asset,
                            module='os',
                            description=description,
                            rule_type=rule_type,
                            match_value=match_value
                        )

                        # 添加到模块级缓存 - 同时缓存基本规则和行为
                        self.result_cache.add(cache_key)
                        self.result_cache.add(behavior_cache_key)

                        # 添加到全局缓存
                        if scanner and hasattr(scanner, 'add_result_to_cache'):
                            scanner.add_result_to_cache(asset.id, 'os', description, rule_type, match_value)

                        if not existing:
                            scan_result = await helpers.save_scan_result(
                                asset=asset,
                                module='os',
                                scan_type='active',
                                description=description,
                                rule_type=rule_type,
                                match_value=match_value,
                                behavior=behavior,
                                request_data=active_request_data,
                                response_data=active_response_data
                            )

                            print(f"保存OS主动扫描结果: 资产={asset.host}, 描述={description}, 行为={behavior}")

                            # 发送扫描结果事件 - 修改结果发送格式，使用asset.host代替ID
                            await channel_layer.group_send(
                                'data_collection_scanner',
                                {
                                    'type': 'scan_result',
                                    'data': {
                                        'id': scan_result.id if scan_result else None,
                                        'asset': asset.host,  # 使用主机名而不是ID
                                        'asset_host': asset.host,  # 添加资产主机名
                                        'module': 'os',
                                        'module_display': '操作系统信息',
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
                            print(f"跳过重复的OS主动扫描结果: 资产={asset.host}, 描述={description}, 行为={behavior}")
                    else:
                        print(f"OS行为 {behavior} 没有匹配结果")

                except asyncio.TimeoutError:
                    print(f"OS主动扫描行为 {behavior} 超时")
                    continue
                except Exception as e:
                    print(f"OS主动扫描行为 {behavior} 出错: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    continue

    async def scan_url(self, url, behavior, rule_type, match_values, use_proxy=False, proxy_address=None):
        """
        根据规则扫描操作系统信息

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
        # 记录扫描开始
        print(f"OS扫描开始: URL={url}, 行为={behavior}, 规则类型={rule_type}")

        # 解析原始URL，获取基本域名和协议
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # 构建目标URL（基本URL + 行为路径）
        target_url = urljoin(base_url, behavior)
        print(f"OS扫描目标URL: {target_url}")

        # 设置代理
        proxy = None
        if use_proxy and proxy_address:
            proxy = proxy_address
            print(f"OS扫描使用代理: {proxy}")

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
                async with session.get(
                        target_url,
                        headers=headers,
                        proxy=proxy,
                        ssl=False,  # 忽略SSL证书验证
                        timeout=aiohttp.ClientTimeout(total=10)  # 设置超时
                ) as response:
                    # 获取响应状态码
                    status_code = response.status
                    print(f"收到响应，状态码: {status_code}")

                    # 获取响应头
                    resp_headers = {}
                    for key, value in response.headers.items():
                        safe_key = self.safe_decode(key)
                        safe_value = self.safe_decode(value)
                        resp_headers[safe_key] = safe_value

                    # 获取响应内容
                    resp_content = await response.text(errors='ignore')
                    print(f"响应内容长度: {len(resp_content)} 字节")

                    # 根据规则类型进行匹配
                    if rule_type == 'status_code':
                        # 状态码判断
                        if str(status_code) in match_values:
                            print(f"OS扫描匹配成功: 状态码 {status_code}")
                            return {'match_value': str(status_code)}

                    elif rule_type == 'response_content':
                        # 响应内容匹配
                        for match_value in match_values:
                            if match_value.lower() in resp_content.lower():
                                print(f"OS扫描匹配成功: 响应内容包含 {match_value}")
                                return {'match_value': match_value}

                    elif rule_type == 'header':
                        # HTTP头匹配
                        for match_value in match_values:
                            header_name, header_value = match_value.split(':', 1) if ':' in match_value else (
                                match_value, '')
                            header_name = header_name.strip()
                            header_value = header_value.strip()

                            if header_name in resp_headers:
                                if not header_value or header_value.lower() in resp_headers[header_name].lower():
                                    print(f"OS扫描匹配成功: HTTP头 {header_name} 包含 {header_value}")
                                    return {'match_value': match_value}

            # 没有匹配结果
            print(f"OS扫描没有匹配结果")
            return None

        except aiohttp.ClientConnectorError as e:
            print(f"OS扫描连接错误: {str(e)}")
            return None
        except aiohttp.ClientError as e:
            print(f"OS扫描HTTP客户端错误: {str(e)}")
            return None
        except asyncio.TimeoutError:
            print(f"OS扫描请求超时")
            return None
        except Exception as e:
            print(f"OS扫描出错: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    async def detect_os_by_case_sensitivity(self, url, use_proxy=False, proxy_address=None):
        """
        通过路径大小写敏感性检测操作系统类型

        Linux/Unix系统通常大小写敏感，Windows通常大小写不敏感

        参数:
            url: 目标URL
            use_proxy: 是否使用代理
            proxy_address: 代理地址

        返回:
            操作系统类型 ('windows', 'unix', 'unknown')
        """
        # 解析原始URL
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path

        # 如果路径为空或仅为根路径，则使用默认测试路径
        if not path or path == '/':
            path = '/index.html'

        # 构建大写路径的URL
        upper_path = path.upper()
        upper_url = urljoin(base_url, upper_path)

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
            print(f"开始通过大小写敏感性检测操作系统类型: {url} vs {upper_url}")

            # 创建异步HTTP会话
            async with aiohttp.ClientSession() as session:
                # 发送原始URL请求
                async with session.get(
                        url,
                        headers=headers,
                        proxy=proxy,
                        ssl=False,
                        timeout=aiohttp.ClientTimeout(total=10)
                ) as orig_response:
                    orig_status = orig_response.status
                    orig_content = await orig_response.text(errors='ignore')

                # 发送大写路径URL请求
                async with session.get(
                        upper_url,
                        headers=headers,
                        proxy=proxy,
                        ssl=False,
                        timeout=aiohttp.ClientTimeout(total=10)
                ) as upper_response:
                    upper_status = upper_response.status
                    upper_content = await upper_response.text(errors='ignore')

                # 比较响应
                if orig_status != upper_status:
                    # 状态码不同，可能是Unix/Linux系统（大小写敏感）
                    print(f"检测到Unix/Linux系统: 状态码不同 {orig_status} vs {upper_status}")
                    return 'unix'
                elif orig_content != upper_content:
                    # 内容不同，可能是Unix/Linux系统（大小写敏感）
                    print(f"检测到Unix/Linux系统: 内容不同")
                    return 'unix'
                else:
                    # 响应相同，可能是Windows系统（大小写不敏感）
                    print(f"检测到Windows系统: 响应相同")
                    return 'windows'

        except Exception as e:
            # 扫描出错
            print(f"操作系统检测出错: {str(e)}")
            import traceback
            traceback.print_exc()
            return 'unknown'

    def safe_decode(self, value):
        """安全地解码任何值，处理所有可能的编码错误"""
        if value is None:
            return ""

        if isinstance(value, bytes):
            try:
                return value.decode('utf-8', errors='replace')
            except Exception:
                # 尝试其他编码格式
                for encoding in ['latin1', 'cp1252', 'iso-8859-1', 'gbk']:
                    try:
                        return value.decode(encoding, errors='replace')
                    except:
                        continue

                # 如果所有解码尝试都失败，返回十六进制表示
                try:
                    return f"[二进制数据: {value[:20].hex()}...]"
                except:
                    return "[二进制数据]"

        if isinstance(value, str):
            # 如果已经是字符串，确保它是有效的UTF-8
            try:
                return value.encode('utf-8', errors='replace').decode('utf-8')
            except Exception:
                return "[编码错误的字符串]"

        # 处理其他类型
        try:
            return str(value)
        except Exception:
            return "[无法转换为字符串的对象]"