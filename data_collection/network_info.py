import asyncio
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
            rule_type: 规则类型 (status_code, response_content, header)
            match_values: 匹配值列表
            use_proxy: 是否使用代理
            proxy_address: 代理地址

        返回:
            匹配结果字典，如果没有匹配则返回None
        """
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

    async def scan_ports(self, host, ports):
        """
        扫描主机开放端口

        参数:
            host: 目标主机名或IP
            ports: 端口列表

        返回:
            开放端口列表
        """
        # 使用外部工具（如nmap）或纯Python实现端口扫描
        # 这里为了简单，仅通过尝试连接来检测端口是否开放
        open_ports = []

        for port in ports:
            try:
                # 创建TCP连接
                future = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(future, timeout=2)

                # 连接成功，端口开放
                open_ports.append(port)

                # 关闭连接
                writer.close()
                await writer.wait_closed()

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                # 连接超时或被拒绝，端口关闭
                pass

        return open_ports