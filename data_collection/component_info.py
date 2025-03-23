import asyncio
import aiohttp
import re
from urllib.parse import urlparse, urljoin


class ComponentInfoScanner:
    """
    组件与服务信息扫描模块：负责扫描网站使用的组件和服务
    """

    # 常见组件的特征指纹
    COMMON_SIGNATURES = {
        'WordPress': [
            {'type': 'path', 'value': '/wp-login.php'},
            {'type': 'path', 'value': '/wp-admin/'},
            {'type': 'header', 'name': 'X-Powered-By', 'value': 'WordPress'},
            {'type': 'content', 'value': 'wp-content'},
        ],
        'Joomla': [
            {'type': 'path', 'value': '/administrator/'},
            {'type': 'content', 'value': 'Joomla!'},
            {'type': 'content', 'value': '/media/jui/'},
        ],
        'Drupal': [
            {'type': 'path', 'value': '/user/login'},
            {'type': 'content', 'value': 'Drupal.settings'},
            {'type': 'content', 'value': '/sites/default/files'},
        ],
        'Apache': [
            {'type': 'header', 'name': 'Server', 'value': 'Apache'},
            {'type': 'path', 'value': '/server-status'},
        ],
        'Nginx': [
            {'type': 'header', 'name': 'Server', 'value': 'nginx'},
        ],
        'IIS': [
            {'type': 'header', 'name': 'Server', 'value': 'Microsoft-IIS'},
        ],
        'PHP': [
            {'type': 'header', 'name': 'X-Powered-By', 'value': 'PHP'},
            {'type': 'path', 'value': '/phpinfo.php'},
        ],
        'ASP.NET': [
            {'type': 'header', 'name': 'X-Powered-By', 'value': 'ASP.NET'},
            {'type': 'header', 'name': 'X-AspNet-Version', 'value': ''},
        ],
        'jQuery': [
            {'type': 'content', 'value': 'jquery'},
        ],
        'Bootstrap': [
            {'type': 'content', 'value': 'bootstrap'},
        ],
        'Laravel': [
            {'type': 'content', 'value': 'laravel'},
            {'type': 'path', 'value': '/vendor/laravel'},
        ],
        'Django': [
            {'type': 'header', 'name': 'X-Framework', 'value': 'Django'},
            {'type': 'content', 'value': 'csrfmiddlewaretoken'},
        ],
    }

    async def scan(self, url, behavior, rule_type, match_values, use_proxy=False, proxy_address=None):
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
            print(f"组件与服务信息扫描出错: {str(e)}")
            return None

    async def detect_components(self, url, use_proxy=False, proxy_address=None):
        """
        检测网站使用的组件和服务

        参数:
            url: 目标URL
            use_proxy: 是否使用代理
            proxy_address: 代理地址

        返回:
            检测到的组件列表
        """
        # 解析原始URL
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

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

        detected_components = []

        try:
            # 创建异步HTTP会话
            async with aiohttp.ClientSession() as session:
                # 首先请求主页
                async with session.get(
                        base_url,
                        headers=headers,
                        proxy=proxy,
                        ssl=False,
                        timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    # 获取响应头
                    resp_headers = dict(response.headers)

                    # 获取响应内容
                    resp_content = await response.text(errors='ignore')

                    # 检查每个组件的特征指纹
                    for component, signatures in self.COMMON_SIGNATURES.items():
                        for signature in signatures:
                            if signature['type'] == 'header':
                                # 检查HTTP头
                                header_name = signature['name']
                                header_value = signature.get('value', '')

                                if header_name in resp_headers:
                                    if not header_value or header_value.lower() in resp_headers[header_name].lower():
                                        if component not in detected_components:
                                            detected_components.append(component)

                            elif signature['type'] == 'content':
                                # 检查响应内容
                                content_value = signature['value']

                                if content_value.lower() in resp_content.lower():
                                    if component not in detected_components:
                                        detected_components.append(component)

                # 请求特定路径
                for component, signatures in self.COMMON_SIGNATURES.items():
                    for signature in signatures:
                        if signature['type'] == 'path':
                            path_value = signature['value']
                            path_url = urljoin(base_url, path_value)

                            try:
                                async with session.get(
                                        path_url,
                                        headers=headers,
                                        proxy=proxy,
                                        ssl=False,
                                        timeout=aiohttp.ClientTimeout(total=5)
                                ) as path_response:
                                    # 如果请求成功（状态码200），则认为检测到了组件
                                    if path_response.status == 200:
                                        if component not in detected_components:
                                            detected_components.append(component)

                            except:
                                # 忽略路径请求错误
                                pass

        except Exception as e:
            # 扫描出错
            print(f"组件检测出错: {str(e)}")

        return detected_components