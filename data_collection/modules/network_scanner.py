"""
网络信息扫描模块：负责扫描网络相关信息
重构版：模仿漏洞扫描模块架构，减少代码重复，加强去重逻辑
"""
import asyncio
import time
from urllib.parse import urlparse, urljoin
import socket
import binascii


class NetworkScanner:
    """网络信息扫描模块类"""

    def __init__(self):
        """初始化扫描器"""
        # 添加结果缓存，避免重复发送相同结果
        # 格式: (asset_id, module, rule_type, description)
        self.result_cache = set()

        # 为每个资产的端口扫描添加时间戳记录
        # 格式: {(asset_id, 'port'): timestamp}
        self.port_scan_timestamps = {}

        # 端口扫描最小间隔(秒)
        self.port_scan_interval = 3600  # 默认1小时

        # 添加缓存来记录已扫描过的资产和端口组合
        self.port_scan_cache = set()  # 缓存格式：(host, port1,port2,...)
        # 添加记录已发现的开放端口
        self.discovered_ports = {}  # 格式：{host: set(ports)}

        # 添加全局锁，防止并发写入
        self.scan_lock = asyncio.Lock()

    def clear_cache(self):
        """清除缓存"""
        self.result_cache.clear()
        self.port_scan_timestamps.clear()
        self.port_scan_cache.clear()
        self.discovered_ports.clear()
        print("网络扫描器缓存已清除")

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

        # 获取全局扫描器实例的方法用于检查和添加全局缓存
        scanner = context.get('scanner')

        # 格式化请求和响应数据，用于保存
        request_data = helpers.format_request_data(method, url, req_headers, req_content)
        response_data = helpers.format_response_data(status_code, resp_headers, resp_content)

        # 获取主动扫描规则
        active_rules = await helpers.get_rules('network', 'active')
        print(f"获取到 {len(active_rules)} 条网络模块主动扫描规则")

        # 进行主动扫描
        await self._do_active_scan(
            active_rules=active_rules,
            context=context,
            request_data=request_data,
            response_data=response_data,
            helpers=helpers,
            scanner=scanner
        )

    async def _do_active_scan(self, active_rules, context, request_data, response_data, helpers, scanner=None):
        """执行主动扫描，增强去重逻辑"""
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
            cache_key = (asset.id, 'network', rule_type, description)

            # 对端口扫描规则的特殊处理
            if rule_type == 'port':
                # 为每个资产的端口扫描创建唯一键
                port_scan_key = (asset.id, 'port')

                # 获取当前时间戳
                current_time = time.time()

                # 检查是否在规定时间间隔内已经扫描过
                last_scan_time = self.port_scan_timestamps.get(port_scan_key, 0)
                time_diff = current_time - last_scan_time

                if time_diff < self.port_scan_interval:
                    print(f"跳过端口扫描，资产 {asset.host} 在 {time_diff:.2f} 秒前已扫描 (最小间隔: {self.port_scan_interval} 秒)")
                    continue

                try:
                    # 解析URL获取主机名
                    parsed_url = urlparse(url)
                    host = parsed_url.netloc

                    # 处理带端口号的主机名
                    if ':' in host:
                        host = host.split(':')[0]

                    print(f"准备对主机 {host} 进行端口扫描, 端口列表: {match_values}")

                    # 开始端口扫描
                    scan_result = await self.scan_ports(host, match_values, use_proxy, proxy_address)

                    # 如果有匹配结果，保存扫描结果
                    if scan_result:
                        match_value = scan_result.get('match_value', '')
                        print(f"端口扫描有结果: {match_value}")

                        # 构建端口扫描的请求和响应数据
                        port_request_data = f"PORT SCAN {host}\nPorts: {', '.join(match_values)}"
                        port_response_data = f"Open ports: {match_value}"

                        # 使用异步锁保护数据库操作
                        async with self.scan_lock:
                            # 二次检查数据库是否已存在相同结果
                            existing = await helpers.check_existing_result(
                                asset=asset,
                                module='network',
                                description=description,
                                rule_type=rule_type,
                                match_value=match_value
                            )

                            # 检查全局缓存
                            global_cache_hit = False
                            if scanner and hasattr(scanner, 'is_result_in_cache') and scanner.is_result_in_cache(
                                    asset.id, 'network', description, rule_type, match_value):
                                global_cache_hit = True
                                print(f"全局缓存命中: {cache_key}")

                            # 检查模块级缓存
                            local_cache_hit = cache_key in self.result_cache
                            if local_cache_hit:
                                print(f"本地缓存命中: {cache_key}")

                            # 如果缓存命中或数据库已存在，跳过
                            if global_cache_hit or local_cache_hit or existing:
                                print(f"跳过重复的端口扫描结果: 资产={asset.host}, 描述={description}")

                                # 即使跳过，也更新时间戳
                                self.port_scan_timestamps[port_scan_key] = current_time
                                continue

                            # 添加到模块级缓存
                            self.result_cache.add(cache_key)

                            # 更新端口扫描时间戳
                            self.port_scan_timestamps[port_scan_key] = current_time

                            # 添加到全局缓存
                            if scanner and hasattr(scanner, 'add_result_to_cache'):
                                scanner.add_result_to_cache(asset.id, 'network', description, rule_type, match_value)

                            # 保存到数据库
                            try:
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
                            except Exception as db_error:
                                print(f"保存端口扫描结果到数据库时出错: {str(db_error)}")
                                import traceback
                                traceback.print_exc()
                    else:
                        print(f"端口扫描无匹配结果")
                        # 即使没有匹配结果，也更新时间戳，避免频繁扫描
                        self.port_scan_timestamps[port_scan_key] = current_time

                except asyncio.TimeoutError:
                    print(f"端口扫描超时")
                    # 超时也更新时间戳
                    self.port_scan_timestamps[port_scan_key] = current_time
                    continue
                except Exception as e:
                    print(f"端口扫描出错: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    continue

                # 端口扫描规则处理完毕，继续下一个规则
                continue

            # 其他类型的主动扫描规则(非端口扫描)
            if not behaviors:
                print(f"规则 {rule_id} ({description}) 没有行为定义，跳过")
                continue

            print(f"准备对资产 {asset.host} 执行主动扫描规则 {rule_id} ({description})")
            print(f"行为列表: {behaviors}")

            for behavior in behaviors:
                try:
                    # 构建行为特定的缓存键
                    behavior_cache_key = f"{cache_key}-{behavior}"

                    # 构建主动扫描URL
                    target_url = urljoin(url, behavior)
                    print(f"执行主动扫描: {target_url}, 行为: {behavior}")

                    # 检查本地缓存
                    if behavior_cache_key in self.result_cache:
                        print(f"跳过本地缓存中已存在的主动扫描结果: {behavior_cache_key}")
                        continue

                    # 设置超时
                    scan_result = await self.scan_url(
                        url=url,
                        behavior=behavior,
                        rule_type=rule_type,
                        match_values=match_values,
                        use_proxy=use_proxy,
                        proxy_address=proxy_address,
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

                        # 使用异步锁保护数据库操作
                        async with self.scan_lock:
                            # 二次检查数据库是否已存在相同结果
                            existing = await helpers.check_existing_result(
                                asset=asset,
                                module='network',
                                description=description,
                                rule_type=rule_type,
                                match_value=match_value
                            )

                            # 检查全局缓存
                            global_cache_hit = False
                            if scanner and hasattr(scanner, 'is_result_in_cache') and scanner.is_result_in_cache(
                                    asset.id, 'network', description, rule_type, match_value):
                                global_cache_hit = True
                                print(f"全局缓存命中: {behavior_cache_key}")

                            # 再次检查本地缓存(可能在锁等待期间被其他任务修改)
                            local_cache_hit = behavior_cache_key in self.result_cache
                            if local_cache_hit:
                                print(f"本地缓存命中(二次检查): {behavior_cache_key}")

                            # 如果缓存命中或数据库已存在，跳过
                            if global_cache_hit or local_cache_hit or existing:
                                print(f"跳过重复的主动扫描结果: 资产={asset.host}, 描述={description}, 行为={behavior}")
                                continue

                            # 添加到本地缓存
                            self.result_cache.add(behavior_cache_key)
                            self.result_cache.add(cache_key)  # 同时添加不带行为的基础缓存键

                            # 添加到全局缓存
                            if scanner and hasattr(scanner, 'add_result_to_cache'):
                                scanner.add_result_to_cache(asset.id, 'network', description, rule_type, match_value)

                            # 保存到数据库
                            try:
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

                                print(f"保存主动扫描结果: 资产={asset.host}, 描述={description}, 行为={behavior}, 匹配值={match_value}")

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
                            except Exception as db_error:
                                print(f"保存主动扫描结果到数据库时出错: {str(db_error)}")
                                import traceback
                                traceback.print_exc()
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

    async def scan_ports(self, host, ports, use_proxy=False, proxy_address=None):
        """
        扫描端口

        参数:
            host: 目标主机
            ports: 要扫描的端口列表
            use_proxy: 是否使用代理
            proxy_address: 代理地址

        返回:
            扫描结果字典
        """
        print(f"开始扫描主机 {host} 的端口: {ports}")

        # 检查缓存
        cache_key = (host, ','.join(sorted(ports)))
        if cache_key in self.port_scan_cache:
            print(f"使用缓存的端口扫描结果: {cache_key}")
            if host in self.discovered_ports:
                # 格式化缓存结果
                results = []
                for port in self.discovered_ports[host]:
                    results.append(f"{port}: 开放")
                return {'match_value': '\n'.join(results)} if results else None
            return None

        # 添加到缓存
        self.port_scan_cache.add(cache_key)

        # 初始化发现的端口集合
        if host not in self.discovered_ports:
            self.discovered_ports[host] = set()

        results = []
        # 扫描每个端口
        for port in ports:
            try:
                port = int(port)

                # 创建TCP socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)  # 设置超时时间

                # 尝试连接
                result = sock.connect_ex((host, port))
                sock.close()

                # 如果连接成功（返回0），则端口开放
                if result == 0:
                    print(f"端口 {port} 开放")
                    self.discovered_ports[host].add(port)

                    # 尝试获取端口banner
                    banner = await self.get_port_banner(host, port)
                    if banner:
                        results.append(f"{port}: {banner}")
                    else:
                        results.append(f"{port}: 开放")

            except Exception as e:
                print(f"扫描端口 {port} 时出错: {str(e)}")
                continue

        # 如果有发现的端口，返回结果
        if results:
            return {'match_value': '\n'.join(results)}

        return None

    async def scan_url(self, url, behavior, rule_type, match_values, use_proxy=False, proxy_address=None, timeout=10):
        """
        扫描URL

        参数:
            url: 基础URL
            behavior: 行为路径
            rule_type: 规则类型
            match_values: 匹配值列表
            use_proxy: 是否使用代理
            proxy_address: 代理地址
            timeout: 超时时间

        返回:
            扫描结果字典
        """
        import aiohttp

        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
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
                async with session.get(
                        target_url,
                        headers=headers,
                        proxy=proxy,
                        ssl=False,  # 忽略SSL证书验证
                        timeout=aiohttp.ClientTimeout(total=timeout)  # 设置超时
                ) as response:
                    # 获取响应状态码
                    status_code = response.status

                    # 获取响应头
                    resp_headers = {}
                    for key, value in response.headers.items():
                        resp_headers[key] = self.safe_decode(value)

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
                        # HTTP头匹配
                        for match_value in match_values:
                            header_name, header_value = match_value.split(':', 1) if ':' in match_value else (match_value, '')
                            header_name = header_name.strip()
                            header_value = header_value.strip()

                            if header_name in resp_headers:
                                if not header_value or header_value.lower() in resp_headers[header_name].lower():
                                    return {'match_value': match_value}

            # 没有匹配结果
            return None

        except Exception as e:
            print(f"扫描URL {target_url} 时出错: {str(e)}")
            return None

    async def get_port_banner(self, host, port):
        """
        获取端口banner信息

        参数:
            host: 主机名
            port: 端口号

        返回:
            banner字符串，如果获取失败则返回None
        """
        try:
            # 创建TCP socket
            reader, writer = await asyncio.open_connection(host, port)

            # 对常见端口发送特定的请求，以获取更有用的banner
            if port == 80 or port == 8080:
                # HTTP请求
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 22:
                # SSH
                pass  # SSH服务器会自动发送banner
            elif port == 21:
                # FTP
                pass  # FTP服务器会自动发送banner
            elif port == 25 or port == 587:
                # SMTP
                pass  # SMTP服务器会自动发送banner
            elif port == 23:
                # Telnet
                pass  # Telnet服务器会自动发送banner

            # 等待数据发送
            await writer.drain()

            # 设置超时
            try:
                # 读取响应（最多4096字节）
                data = await asyncio.wait_for(reader.read(4096), timeout=3)
            except asyncio.TimeoutError:
                data = None

            # 关闭连接
            writer.close()
            await writer.wait_closed()

            # 处理数据
            if data:
                return self.format_banner_data(data)

            return "端口开放，无banner信息"

        except Exception as e:
            print(f"获取端口 {port} banner时出错: {str(e)}")
            return None

    def format_banner_data(self, data):
        """
        格式化Banner数据，处理可能的乱码问题

        参数:
            data: 二进制Banner数据

        返回:
            格式化后的Banner字符串
        """
        if not data:
            return "端口开放，无banner信息"

        # 策略1: 尝试不同的编码方式
        best_decoded = None
        best_printable_ratio = 0

        # 尝试多种编码
        for encoding in ['utf-8', 'ascii', 'latin1', 'gbk', 'gb2312']:
            try:
                # 解码数据
                decoded = data.decode(encoding, errors='replace')

                # 计算可打印字符比例
                printable_count = sum(1 for c in decoded if c.isprintable() and c != '�')
                printable_ratio = printable_count / len(decoded) if decoded else 0

                # 如果这个编码产生了更高比例的可打印字符，使用它
                if printable_ratio > best_printable_ratio:
                    best_printable_ratio = printable_ratio
                    best_decoded = decoded

                    # 如果几乎全是可打印字符，认为这是正确的编码
                    if printable_ratio > 0.95:
                        break
            except Exception:
                continue

        # 如果没有找到合适的编码或可打印字符比例太低
        if not best_decoded or best_printable_ratio < 0.5:
            # 策略2: 尝试提取ASCII部分
            ascii_text = self.extract_ascii_text(data)
            if ascii_text and len(ascii_text) > 10:  # 至少有10个可读字符
                return ascii_text

            # 策略3: 转为十六进制展示
            hex_data = binascii.hexlify(data[:32]).decode('ascii')
            return f"二进制数据 (前32字节: {hex_data})"

        # 清理解码后的文本
        clean_text = self.clean_banner(best_decoded)

        # 如果清理后的文本很短，可能是因为大部分是不可打印字符被移除了
        if len(clean_text) < 5 and len(data) > 20:
            hex_data = binascii.hexlify(data[:32]).decode('ascii')
            return f"二进制数据 (前32字节: {hex_data})"

        return clean_text

    def clean_banner(self, text):
        """清理Banner文本，移除不可打印字符"""
        if not text:
            return ""

        # 将控制字符(除了常见的空白字符)替换为空格
        cleaned = ""
        for c in text:
            if c.isprintable() or c in [' ', '\t', '\n', '\r']:
                cleaned += c
            else:
                cleaned += ' '

        # 将多个连续空格替换为单个空格
        import re
        cleaned = re.sub(r'\s+', ' ', cleaned)

        # 修剪前后空白
        cleaned = cleaned.strip()

        return cleaned

    def extract_ascii_text(self, data):
        """从二进制数据中提取可读的ASCII文本"""
        if not data:
            return ""

        # 提取ASCII可打印字符 (32-126)
        ascii_chars = []
        for b in data:
            if 32 <= b <= 126:  # ASCII可打印字符范围
                ascii_chars.append(chr(b))
            else:
                # 对于不可打印字符，添加空格作为分隔
                # 但避免添加连续的空格
                if not ascii_chars or ascii_chars[-1] != ' ':
                    ascii_chars.append(' ')

        # 转换为字符串并清理多余空格
        result = ''.join(ascii_chars).strip()

        # 将多个连续空格替换为单个空格
        import re
        result = re.sub(r'\s+', ' ', result)

        return result

    def safe_decode(self, value):
        """安全地解码任何值，处理所有可能的编码错误"""
        if value is None:
            return ""

        if isinstance(value, bytes):
            try:
                # 首先尝试UTF-8解码
                return value.decode('utf-8', errors='replace')
            except Exception:
                # 尝试其他编码
                for encoding in ['latin1', 'cp1252', 'iso-8859-1', 'gbk']:
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