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
        """安全地解码任何值，处理所有可能的编码错误"""
        if value is None:
            return ""

        if isinstance(value, bytes):
            try:
                return value.decode('utf-8', errors='replace')
            except Exception:
                # 如果出现任何问题，返回占位符
                return "[二进制数据]"

        if isinstance(value, str):
            # 如果已经是字符串，确保它是有效的UTF-8
            try:
                return value.encode('utf-8', errors='replace').decode('utf-8')
            except Exception:
                return "[编码错误]"

        # 处理其他类型
        try:
            return str(value)
        except Exception:
            return "[无法转换为字符串]"

    async def scan(self, url, behavior, rule_type, match_values, use_proxy=False, proxy_address=None):
        """
        根据规则扫描网络信息

        参数:
            url: 目标URL
            behavior: 扫描行为（访问路径）
            rule_type: 规则类型 (status_code, response_content, header, port)
            match_values: 匹配值列表
            use_proxy: 是否使用代理
            proxy_address: 代理地址

        返回:
            匹配结果字典，如果没有匹配则返回None
        """
        # 特殊处理端口扫描规则
        if rule_type == 'port':
            # 从URL解析主机名
            parsed_url = urlparse(url)
            host = parsed_url.netloc

            # 处理带端口号的主机名
            if ':' in host:
                host = host.split(':')[0]

            # 将匹配值解析为端口列表
            ports = []
            for port_str in match_values:
                try:
                    # 尝试将端口值转换为整数
                    port = int(port_str.strip())
                    ports.append(port)
                except ValueError:
                    # 如果不是有效的端口号，跳过
                    continue

            # 创建用于缓存检查的键
            ports_tuple = tuple(sorted(ports))  # 排序确保相同端口集合生成相同的键
            cache_key = (host, ports_tuple)

            # 检查是否已经扫描过此主机和端口组合
            if cache_key in self.port_scan_cache:
                print(f"跳过重复的端口扫描: 主机={host}, 端口={ports}")

                # 如果已扫描但有之前的结果，返回之前的结果
                if host in self.discovered_ports and self.discovered_ports[host]:
                    open_ports = self.discovered_ports[host]
                    print(f"返回缓存的端口扫描结果: 主机={host}, 开放端口={open_ports}")

                    # 格式化返回结果
                    result_value = []
                    for port in open_ports:
                        result_value.append(f"{port}:端口开放，无banner信息")

                    if result_value:
                        return {'match_value': '\n'.join(result_value)}

                return None  # 如果没有缓存的结果，返回None表示不需要再次扫描

            # 添加到缓存中标记为已扫描
            self.port_scan_cache.add(cache_key)

            # 执行端口扫描 - 现在只扫描未扫描过的端口
            open_ports_info = await self.scan_ports_with_banner(host, ports)

            # 如果有开放端口，更新已发现端口缓存
            if open_ports_info:
                if host not in self.discovered_ports:
                    self.discovered_ports[host] = set()

                # 添加新发现的端口
                for port in open_ports_info.keys():
                    self.discovered_ports[host].add(port)

                # 将端口和banner信息格式化为字符串
                result_value = []
                for port, banner in open_ports_info.items():
                    result_value.append(f"{port}:{banner}")

                return {'match_value': '\n'.join(result_value)}
            else:
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
                        if safe_key != "[编码错误]" and safe_value != "[编码错误]":
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
                                if not header_name or header_name in ["[编码错误]", "[二进制数据]"]:
                                    print(f"无效的HTTP头名称: {header_name}")
                                    continue

                                # 检查头是否存在
                                if header_name in resp_headers:
                                    actual_value = resp_headers[header_name]
                                    # 如果没有指定值，或者值包含在实际值中
                                    if not header_value or (header_value.lower() in actual_value.lower()):
                                        return {'match_value': match_value}
                            except Exception as e:
                                print(f"处理HTTP头匹配值时出错: {str(e)}")
                                continue

            # 没有匹配结果
            return None

        except aiohttp.ClientConnectorError:
            # 连接错误，可能是端口关闭
            return None
        except aiohttp.ClientError:
            # 其他HTTP客户端错误
            return None
        except asyncio.TimeoutError:
            # 请求超时
            return None
        except Exception as e:
            # 其他错误
            print(f"网络信息扫描出错: {str(e)}")
            return None

    async def scan_ports_with_banner(self, host, ports, timeout=2):
        """
        扫描主机开放端口并获取Banner信息

        参数:
            host: 目标主机名或IP
            ports: 端口列表
            timeout: 超时时间（秒）

        返回:
            开放端口及其Banner信息的字典 {端口号: banner内容}
        """
        open_ports_info = {}
        tasks = []

        # 限制最多扫描20个端口，防止过多任务
        if len(ports) > 20:
            ports = ports[:20]

        for port in ports:
            task = asyncio.create_task(self.get_port_banner(host, port, timeout))
            tasks.append((port, task))

        # 等待所有任务完成
        for port, task in tasks:
            try:
                banner = await task
                if banner is not None:  # 端口开放
                    # 确保相同端口不重复记录
                    if port not in open_ports_info:
                        open_ports_info[port] = banner
            except Exception as e:
                print(f"端口 {port} 扫描出错: {str(e)}")

        return open_ports_info

    async def get_port_banner(self, host, port, timeout=2):
        """
        检查端口并获取Banner信息 - 纯被动方式，不发送任何数据

        参数:
            host: 目标主机
            port: 目标端口
            timeout: 超时时间（秒）

        返回:
            如果端口开放，返回banner内容（字符串）；否则返回None
        """
        try:
            # 创建socket并设置超时
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )

            try:
                # 等待接收banner（一些服务会直接发送banner）
                # 限制初始读取超时为1秒，避免长时间等待
                initial_data = b''
                try:
                    initial_data = await asyncio.wait_for(
                        reader.read(1024),
                        timeout=1
                    )
                except asyncio.TimeoutError:
                    # 超时但端口已连接，继续处理
                    pass

                # 无论是否接收到数据，都返回一个有效的Banner
                if initial_data:
                    # 处理收到的数据
                    return self.format_banner_data(initial_data)
                else:
                    # 没有收到初始数据，仅确认端口开放
                    return "端口开放，无banner信息"

            except Exception as e:
                # 连接后出错，但端口是开放的
                print(f"读取端口 {port} Banner时出错: {str(e)}")
                return "端口开放，无banner信息"
            finally:
                # 确保关闭连接
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass

            return "端口开放，无banner信息"

        except (asyncio.TimeoutError, ConnectionRefusedError, socket.error):
            # 连接失败，端口关闭
            return None
        except Exception as e:
            print(f"尝试连接端口 {port} 时出错: {str(e)}")
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

    def clear_cache(self):
        """清除扫描缓存"""
        self.port_scan_cache.clear()
        self.discovered_ports.clear()
        print("已清除端口扫描缓存")

    def get_cache_size(self):
        """获取当前缓存大小"""
        return len(self.port_scan_cache)