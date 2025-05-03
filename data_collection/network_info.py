import asyncio
import socket
import binascii
import aiohttp
from urllib.parse import urlparse, urljoin


class NetworkInfoScanner:
    """
    网络信息扫描模块：负责扫描网络相关信息
    """

    def __init__(self):
        """初始化扫描器"""
        # 添加缓存来记录已扫描过的资产和端口组合
        self.port_scan_cache = set()  # 缓存格式：(host, port1,port2,...)
        # 添加记录已发现的开放端口
        self.discovered_ports = {}  # 格式：{host: set(ports)}

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

    def clear_cache(self):
        """清除扫描缓存"""
        self.port_scan_cache.clear()
        self.discovered_ports.clear()
        print("已清除端口扫描缓存")

    def get_cache_size(self):
        """获取当前缓存大小"""
        return len(self.port_scan_cache)

    async def scan(self, url, behavior, rule_type, match_values, use_proxy=False, proxy_address=None):
        """
        扫描网络信息

        参数:
            url: 目标URL
            behavior: 扫描行为
            rule_type: 规则类型
            match_values: 匹配值列表
            use_proxy: 是否使用代理
            proxy_address: 代理地址

        返回:
            匹配结果字典，如果没有匹配则返回None
        """
        print(f"网络扫描开始: URL={url}, 行为={behavior}, 规则类型={rule_type}")

        # 对端口扫描的特殊处理
        if rule_type == 'port':
            return await self.scan_ports(url, match_values, use_proxy, proxy_address)

        # 其他网络扫描规则的处理
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
                        ssl=False,
                        timeout=aiohttp.ClientTimeout(total=10)
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
                            if ':' in match_value:
                                header_parts = match_value.split(':', 1)
                                header_name = header_parts[0].strip()
                                header_value = header_parts[1].strip()
                            else:
                                header_name = match_value.strip()
                                header_value = ''

                            if header_name in resp_headers:
                                if not header_value or header_value.lower() in resp_headers[header_name].lower():
                                    return {'match_value': match_value}

            # 没有匹配结果
            return None

        except Exception as e:
            print(f"网络扫描出错: {str(e)}")
            return None

    async def scan_ports(self, url, ports, use_proxy=False, proxy_address=None):
        """
        扫描端口

        参数:
            url: 目标URL
            ports: 要扫描的端口列表
            use_proxy: 是否使用代理
            proxy_address: 代理地址

        返回:
            扫描结果字典
        """
        # 从URL解析主机名
        parsed_url = urlparse(url)
        host = parsed_url.netloc

        # 处理带端口号的主机名
        if ':' in host:
            host = host.split(':')[0]

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