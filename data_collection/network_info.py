import asyncio
import socket
import aiohttp
from urllib.parse import urlparse, urljoin


class NetworkInfoScanner:
    """
    网络信息扫描模块：负责扫描网络相关信息
    """

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

            # 执行端口扫描
            open_ports_info = await self.scan_ports_with_banner(host, ports)

            # 如果有开放端口，返回匹配结果
            if open_ports_info:
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

                    # 获取响应头
                    resp_headers = dict(response.headers)

                    # 获取响应内容
                    resp_content = await response.text(errors='ignore')

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
                            header_name, header_value = match_value.split(':', 1) if ':' in match_value else (
                                match_value, '')
                            header_name = header_name.strip()
                            header_value = header_value.strip()

                            if header_name in resp_headers:
                                if not header_value or header_value.lower() in resp_headers[header_name].lower():
                                    return {'match_value': match_value}

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

        for port in ports:
            task = asyncio.create_task(self.get_port_banner(host, port, timeout))
            tasks.append((port, task))

        # 等待所有任务完成
        for port, task in tasks:
            try:
                banner = await task
                if banner is not None:  # 端口开放
                    open_ports_info[port] = banner
            except Exception as e:
                print(f"端口 {port} 扫描出错: {str(e)}")

        return open_ports_info

    async def get_port_banner(self, host, port, timeout=2):
        """
        检查端口并获取Banner信息

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
                banner_data = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=1
                )

                # 如果没有收到数据，尝试发送一些通用的请求
                if not banner_data:
                    # 尝试HTTP请求
                    if port in [80, 443, 8080, 8443]:
                        writer.write(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                        await writer.drain()
                    # 尝试SMTP
                    elif port in [25, 465]:
                        writer.write(b"EHLO example.com\r\n")
                        await writer.drain()
                    # 尝试FTP
                    elif port == 21:
                        writer.write(b"USER anonymous\r\n")
                        await writer.drain()
                    # 尝试POP3
                    elif port in [110, 995]:
                        writer.write(b"CAPA\r\n")
                        await writer.drain()
                    # 尝试通用的查询命令
                    else:
                        writer.write(b"HELP\r\n")
                        await writer.drain()

                    # 再次尝试读取数据
                    banner_data = await asyncio.wait_for(
                        reader.read(1024),
                        timeout=1
                    )

                # 转换为字符串并清理
                banner = banner_data.decode('utf-8', errors='ignore').strip()

                # 截断过长的banner
                if len(banner) > 100:
                    banner = banner[:100] + "..."

                # 如果banner为空，至少返回端口开放信息
                if not banner:
                    banner = "端口开放，无banner信息"

            except asyncio.TimeoutError:
                # 读取超时，但端口是开放的
                banner = "端口开放，无banner信息"
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass

            return banner

        except (asyncio.TimeoutError, ConnectionRefusedError, socket.error):
            # 连接失败，端口关闭
            return None
        except Exception as e:
            print(f"尝试连接端口 {port} 时出错: {str(e)}")
            return None