import asyncio
import aiohttp
from urllib.parse import urlparse, urljoin


class OSInfoScanner:
    """
    操作系统信息扫描模块：负责扫描操作系统相关信息
    """

    async def scan(self, url, behavior, rule_type, match_values, use_proxy=False, proxy_address=None):
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

        except Exception as e:
            # 扫描出错
            print(f"操作系统信息扫描出错: {str(e)}")
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
                    return 'unix'
                elif orig_content != upper_content:
                    # 内容不同，可能是Unix/Linux系统（大小写敏感）
                    return 'unix'
                else:
                    # 响应相同，可能是Windows系统（大小写不敏感）
                    return 'windows'

        except Exception as e:
            # 扫描出错
            print(f"操作系统检测出错: {str(e)}")
            return 'unknown'