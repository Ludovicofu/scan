# vuln_scan/modules/rce_scanner.py
import re
import asyncio
import aiohttp
import random
import string
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from async_timeout import timeout
from utils.http_utils import parse_http_request, rebuild_http_request
from utils.payload_utils import replace_parameter


class RceScanner:
    """
    RCE扫描器：检测远程代码执行漏洞，包括系统命令执行和代码执行
    """

    def __init__(self):
        """初始化RCE扫描器"""
        # 系统命令执行载荷的默认列表
        self.os_command_payloads = [
            "|echo cmd_inj_test",
            ";echo cmd_inj_test",
            "`echo cmd_inj_test`",
            "$(echo cmd_inj_test)",
            "&& echo cmd_inj_test",
            "|| echo cmd_inj_test"
        ]

        # 代码执行载荷的默认列表
        self.code_execution_payloads = [
            "<?php echo 'code_inj_test'; ?>",
            "${system('echo code_inj_test')}",
            "eval(\"print('code_inj_test')\")",
            "exec('echo code_inj_test')"
        ]

        # 命令执行匹配模式
        self.command_patterns = [
            "cmd_inj_test",
            "uid=",
            "gid=",
            "groups="
        ]

        # 代码执行匹配模式
        self.code_patterns = [
            "code_inj_test",
            "PHP Version",
            "eval()"
        ]

        # 已扫描的URLs缓存
        self.scanned_urls = set()

    def clear_cache(self):
        """清除缓存"""
        self.scanned_urls.clear()

    async def load_payloads(self, rules_api):
        """从规则API加载载荷"""
        try:
            # 获取系统命令执行载荷
            os_command_rules = await rules_api.get_rules_by_type_and_subtype('command_injection', 'os_command')
            if os_command_rules and len(os_command_rules) > 0:
                rule_content = json.loads(os_command_rules[0]['rule_content'])
                if 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
                    self.os_command_payloads = rule_content['payloads']

            # 获取代码执行载荷
            code_execution_rules = await rules_api.get_rules_by_type_and_subtype('command_injection', 'code_injection')
            if code_execution_rules and len(code_execution_rules) > 0:
                rule_content = json.loads(code_execution_rules[0]['rule_content'])
                if 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
                    self.code_execution_payloads = rule_content['payloads']

            # 获取匹配模式
            pattern_rules = await rules_api.get_rules_by_type_and_subtype('command_injection', 'match_patterns')
            if pattern_rules and len(pattern_rules) > 0:
                rule_content = json.loads(pattern_rules[0]['rule_content'])
                if 'patterns' in rule_content and isinstance(rule_content['patterns'], dict):
                    if 'os_command' in rule_content['patterns'] and isinstance(rule_content['patterns']['os_command'],
                                                                               list):
                        self.command_patterns = rule_content['patterns']['os_command']
                    if 'code_injection' in rule_content['patterns'] and isinstance(
                            rule_content['patterns']['code_injection'], list):
                        self.code_patterns = rule_content['patterns']['code_injection']
        except Exception as e:
            print(f"加载RCE载荷时出错: {str(e)}")

    async def scan(self, context):
        """
        扫描RCE漏洞

        参数:
            context: 扫描上下文，包含URL、请求头、请求体、响应等信息

        返回:
            漏洞列表
        """
        url = context.get('url', '')
        method = context.get('method', 'GET')
        req_headers = context.get('req_headers', {})
        req_content = context.get('req_content', '')
        resp_headers = context.get('resp_headers', {})
        resp_content = context.get('resp_content', '')
        use_proxy = context.get('use_proxy', False)
        proxy_address = context.get('proxy_address', 'http://localhost:7890')
        scan_timeout = context.get('scan_timeout', 10)
        asset_id = context.get('asset', None)

        # 检查URL是否已扫描过
        if url in self.scanned_urls:
            return []

        # 添加到已扫描列表
        self.scanned_urls.add(url)

        # 解析URL和请求参数
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # 解析请求体参数
        body_params = {}
        if method == 'POST':
            try:
                if 'Content-Type' in req_headers and 'application/json' in req_headers['Content-Type']:
                    body_params = json.loads(req_content)
                elif 'Content-Type' in req_headers and 'application/x-www-form-urlencoded' in req_headers[
                    'Content-Type']:
                    body_params = parse_qs(req_content)
                elif 'Content-Type' in req_headers and 'multipart/form-data' in req_headers['Content-Type']:
                    # 简单处理multipart/form-data，仅提取键值对
                    matches = re.findall(r'name="([^"]+)"\r\n\r\n([^\r]+)', req_content)
                    for key, value in matches:
                        body_params[key] = [value]
            except Exception as e:
                print(f"解析请求体参数时出错: {str(e)}")

        # 扫描结果列表
        results = []

        # 扫描GET参数
        if query_params:
            url_results = await self.scan_url_params(
                url,
                parsed_url,
                query_params,
                resp_content,
                use_proxy,
                proxy_address,
                scan_timeout,
                asset_id
            )
            results.extend(url_results)

        # 扫描POST参数
        if method == 'POST' and body_params:
            post_results = await self.scan_post_params(
                url,
                method,
                req_headers,
                body_params,
                resp_content,
                use_proxy,
                proxy_address,
                scan_timeout,
                asset_id
            )
            results.extend(post_results)

        return results

    async def scan_url_params(self, url, parsed_url, query_params, resp_content, use_proxy, proxy_address, scan_timeout,
                              asset_id):
        """
        扫描URL参数中的RCE漏洞

        参数:
            url: 原始URL
            parsed_url: 解析后的URL
            query_params: 查询参数
            resp_content: 原始响应内容
            use_proxy: 是否使用代理
            proxy_address: 代理地址
            scan_timeout: 扫描超时时间
            asset_id: 资产ID

        返回:
            漏洞列表
        """
        results = []

        # 测试每个参数
        for param_name, param_values in query_params.items():
            param_value = param_values[0] if param_values else ''

            # 测试命令执行漏洞
            os_command_results = await self.test_os_command_injection(
                url,
                parsed_url,
                param_name,
                param_value,
                'url',
                resp_content,
                use_proxy,
                proxy_address,
                scan_timeout,
                asset_id
            )
            results.extend(os_command_results)

            # 测试代码执行漏洞
            code_execution_results = await self.test_code_execution(
                url,
                parsed_url,
                param_name,
                param_value,
                'url',
                resp_content,
                use_proxy,
                proxy_address,
                scan_timeout,
                asset_id
            )
            results.extend(code_execution_results)

        return results

    async def scan_post_params(self, url, method, headers, body_params, resp_content, use_proxy, proxy_address,
                               scan_timeout, asset_id):
        """
        扫描POST参数中的RCE漏洞

        参数:
            url: 原始URL
            method: HTTP方法
            headers: 请求头
            body_params: 请求体参数
            resp_content: 原始响应内容
            use_proxy: 是否使用代理
            proxy_address: 代理地址
            scan_timeout: 扫描超时时间
            asset_id: 资产ID

        返回:
            漏洞列表
        """
        results = []

        # 处理不同类型的body参数
        if isinstance(body_params, dict):
            for param_name, param_value in body_params.items():
                if isinstance(param_value, list) and param_value:
                    param_value = param_value[0]
                elif not isinstance(param_value, str):
                    param_value = str(param_value)

                # 测试命令执行漏洞
                os_command_results = await self.test_os_command_injection(
                    url,
                    None,
                    param_name,
                    param_value,
                    'body',
                    resp_content,
                    use_proxy,
                    proxy_address,
                    scan_timeout,
                    asset_id,
                    method=method,
                    headers=headers,
                    body_params=body_params
                )
                results.extend(os_command_results)

                # 测试代码执行漏洞
                code_execution_results = await self.test_code_execution(
                    url,
                    None,
                    param_name,
                    param_value,
                    'body',
                    resp_content,
                    use_proxy,
                    proxy_address,
                    scan_timeout,
                    asset_id,
                    method=method,
                    headers=headers,
                    body_params=body_params
                )
                results.extend(code_execution_results)

        return results

    async def test_os_command_injection(self, url, parsed_url, param_name, param_value, param_type, resp_content,
                                        use_proxy, proxy_address, scan_timeout, asset_id,
                                        method=None, headers=None, body_params=None):
        """
        测试系统命令执行漏洞

        参数:
            url: 原始URL
            parsed_url: 解析后的URL（仅URL参数需要）
            param_name: 参数名
            param_value: 参数值
            param_type: 参数类型 (url或body)
            resp_content: 原始响应内容
            use_proxy: 是否使用代理
            proxy_address: 代理地址
            scan_timeout: 扫描超时时间
            asset_id: 资产ID
            method: HTTP方法（仅POST参数需要）
            headers: 请求头（仅POST参数需要）
            body_params: 请求体参数（仅POST参数需要）

        返回:
            漏洞列表
        """
        results = []

        # 测试每个命令注入载荷
        for payload in self.os_command_payloads:
            try:
                # 构建测试URL或请求体
                test_url = None
                test_headers = None
                test_body = None

                if param_type == 'url' and parsed_url:
                    # 替换URL参数
                    new_params = parse_qs(parsed_url.query)
                    new_params[param_name] = [param_value + payload]
                    new_query = urlencode(new_params, doseq=True)
                    test_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment
                    ))
                elif param_type == 'body' and method and headers and body_params:
                    # 替换请求体参数
                    test_url = url
                    test_headers = headers.copy()
                    test_body = body_params.copy()

                    # 处理不同类型的body参数
                    if isinstance(test_body, dict):
                        if isinstance(test_body.get(param_name), list):
                            test_body[param_name][0] = param_value + payload
                        else:
                            test_body[param_name] = param_value + payload

                if not test_url:
                    continue

                # 发送请求
                async with aiohttp.ClientSession() as session:
                    # 设置代理
                    proxy = proxy_address if use_proxy else None

                    # 设置超时
                    async with timeout(scan_timeout):
                        # 发送GET或POST请求
                        if param_type == 'url' or method == 'GET':
                            async with session.get(test_url, proxy=proxy) as response:
                                test_resp_text = await response.text()
                        else:  # POST
                            # 处理不同Content-Type的请求体
                            if 'Content-Type' in test_headers and 'application/json' in test_headers['Content-Type']:
                                async with session.post(test_url, json=test_body, headers=test_headers,
                                                        proxy=proxy) as response:
                                    test_resp_text = await response.text()
                            elif 'Content-Type' in test_headers and 'application/x-www-form-urlencoded' in test_headers[
                                'Content-Type']:
                                form_data = {}
                                for k, v in test_body.items():
                                    form_data[k] = v[0] if isinstance(v, list) and v else v
                                async with session.post(test_url, data=form_data, headers=test_headers,
                                                        proxy=proxy) as response:
                                    test_resp_text = await response.text()
                            else:
                                # 默认使用form-data
                                form_data = {}
                                for k, v in test_body.items():
                                    form_data[k] = v[0] if isinstance(v, list) and v else v
                                async with session.post(test_url, data=form_data, headers=test_headers,
                                                        proxy=proxy) as response:
                                    test_resp_text = await response.text()

                # 检查响应中是否存在命令执行成功的标志
                if self.check_os_command_response(test_resp_text):
                    # 发现RCE漏洞
                    vuln_result = {
                        'vuln_type': 'command_injection',
                        'vuln_subtype': 'os_command',
                        'asset': asset_id,
                        'name': 'RCE系统命令执行漏洞',
                        'description': f'在{param_type}参数"{param_name}"中存在RCE系统命令执行漏洞',
                        'severity': 'high',
                        'url': url,
                        'request': self.build_request_text(url, param_name, param_value + payload, param_type, method,
                                                           headers, body_params),
                        'response': test_resp_text[:5000] if test_resp_text else '',  # 限制长度
                        'proof': f'系统命令执行载荷: {payload}\n参数名: {param_name}\n执行结果: cmd_inj_test 输出在响应中被检测到',
                        'parameter': param_name,
                        'payload': payload,
                    }
                    results.append(vuln_result)
            except Exception as e:
                print(f"测试系统命令执行漏洞时出错: {str(e)}")

        return results

    async def test_code_execution(self, url, parsed_url, param_name, param_value, param_type, resp_content,
                                  use_proxy, proxy_address, scan_timeout, asset_id,
                                  method=None, headers=None, body_params=None):
        """
        测试代码执行漏洞

        参数:
            url: 原始URL
            parsed_url: 解析后的URL（仅URL参数需要）
            param_name: 参数名
            param_value: 参数值
            param_type: 参数类型 (url或body)
            resp_content: 原始响应内容
            use_proxy: 是否使用代理
            proxy_address: 代理地址
            scan_timeout: 扫描超时时间
            asset_id: 资产ID
            method: HTTP方法（仅POST参数需要）
            headers: 请求头（仅POST参数需要）
            body_params: 请求体参数（仅POST参数需要）

        返回:
            漏洞列表
        """
        results = []

        # 测试每个代码执行载荷
        for payload in self.code_execution_payloads:
            try:
                # 构建测试URL或请求体
                test_url = None
                test_headers = None
                test_body = None

                if param_type == 'url' and parsed_url:
                    # 替换URL参数
                    new_params = parse_qs(parsed_url.query)
                    new_params[param_name] = [param_value + payload]
                    new_query = urlencode(new_params, doseq=True)
                    test_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment
                    ))
                elif param_type == 'body' and method and headers and body_params:
                    # 替换请求体参数
                    test_url = url
                    test_headers = headers.copy()
                    test_body = body_params.copy()

                    # 处理不同类型的body参数
                    if isinstance(test_body, dict):
                        if isinstance(test_body.get(param_name), list):
                            test_body[param_name][0] = param_value + payload
                        else:
                            test_body[param_name] = param_value + payload

                if not test_url:
                    continue

                # 发送请求
                async with aiohttp.ClientSession() as session:
                    # 设置代理
                    proxy = proxy_address if use_proxy else None

                    # 设置超时
                    async with timeout(scan_timeout):
                        # 发送GET或POST请求
                        if param_type == 'url' or method == 'GET':
                            async with session.get(test_url, proxy=proxy) as response:
                                test_resp_text = await response.text()
                        else:  # POST
                            # 处理不同Content-Type的请求体
                            if 'Content-Type' in test_headers and 'application/json' in test_headers['Content-Type']:
                                async with session.post(test_url, json=test_body, headers=test_headers,
                                                        proxy=proxy) as response:
                                    test_resp_text = await response.text()
                            elif 'Content-Type' in test_headers and 'application/x-www-form-urlencoded' in test_headers[
                                'Content-Type']:
                                form_data = {}
                                for k, v in test_body.items():
                                    form_data[k] = v[0] if isinstance(v, list) and v else v
                                async with session.post(test_url, data=form_data, headers=test_headers,
                                                        proxy=proxy) as response:
                                    test_resp_text = await response.text()
                            else:
                                # 默认使用form-data
                                form_data = {}
                                for k, v in test_body.items():
                                    form_data[k] = v[0] if isinstance(v, list) and v else v
                                async with session.post(test_url, data=form_data, headers=test_headers,
                                                        proxy=proxy) as response:
                                    test_resp_text = await response.text()

                # 检查响应中是否存在代码执行成功的标志
                if self.check_code_execution_response(test_resp_text, payload):
                    # 确定代码类型
                    code_type = self.determine_code_type(payload)

                    # 发现RCE漏洞
                    vuln_result = {
                        'vuln_type': 'command_injection',
                        'vuln_subtype': code_type,
                        'asset': asset_id,
                        'name': f'RCE{code_type.replace("_code", "")}代码执行漏洞',
                        'description': f'在{param_type}参数"{param_name}"中存在RCE代码执行漏洞',
                        'severity': 'high',
                        'url': url,
                        'request': self.build_request_text(url, param_name, param_value + payload, param_type, method,
                                                           headers, body_params),
                        'response': test_resp_text[:5000] if test_resp_text else '',  # 限制长度
                        'proof': f'代码执行载荷: {payload}\n参数名: {param_name}\n执行结果: code_inj_test 输出在响应中被检测到',
                        'parameter': param_name,
                        'payload': payload,
                    }
                    results.append(vuln_result)
            except Exception as e:
                print(f"测试代码执行漏洞时出错: {str(e)}")

        return results

    def check_os_command_response(self, response_text):
        """
        检查响应中是否存在命令执行成功的标志

        参数:
            response_text: 响应文本

        返回:
            是否存在命令执行成功的标志
        """
        if not response_text:
            return False

        # 检查是否包含命令执行成功的标志
        for pattern in self.command_patterns:
            if pattern in response_text:
                return True

        return False

    def check_code_execution_response(self, response_text, payload):
        """
        检查响应中是否存在代码执行成功的标志

        参数:
            response_text: 响应文本
            payload: 使用的载荷

        返回:
            是否存在代码执行成功的标志
        """
        if not response_text:
            return False

        # 检查是否包含代码执行成功的标志
        for pattern in self.code_patterns:
            if pattern in response_text:
                return True

        # 检查PHP特有标志
        if '<?php' in payload and ('PHP Version' in response_text or 'php.ini' in response_text):
            return True

        # 检查Python特有标志
        if 'print(' in payload and ('__main__' in response_text or 'IndentationError' in response_text):
            return True

        # 检查Java特有标志
        if 'System.out.println' in payload and (
                'Exception in thread' in response_text or 'java.lang.' in response_text):
            return True

        return False

    def determine_code_type(self, payload):
        """
        确定代码类型

        参数:
            payload: 使用的载荷

        返回:
            代码类型
        """
        if '<?php' in payload or 'php' in payload.lower():
            return 'php_code'
        elif 'System.out.println' in payload or 'java' in payload.lower():
            return 'java_code'
        elif 'print(' in payload or 'python' in payload.lower():
            return 'python_code'
        else:
            return 'code_injection'  # 默认类型

    def build_request_text(self, url, param_name, param_value, param_type, method=None, headers=None, body_params=None):
        """
        构建请求文本

        参数:
            url: URL
            param_name: 参数名
            param_value: 参数值
            param_type: 参数类型 (url或body)
            method: HTTP方法
            headers: 请求头
            body_params: 请求体参数

        返回:
            请求文本
        """
        if param_type == 'url':
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            params[param_name] = [param_value]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))

            request_text = f"GET {new_url} HTTP/1.1\r\n"
            request_text += f"Host: {parsed_url.netloc}\r\n"
            request_text += "User-Agent: Mozilla/5.0\r\n"
            request_text += "Accept: */*\r\n"
            request_text += "\r\n"
        elif param_type == 'body' and method and headers and body_params:
            request_text = f"{method} {url} HTTP/1.1\r\n"
            request_text += f"Host: {urlparse(url).netloc}\r\n"

            # 添加请求头
            for header_name, header_value in headers.items():
                if header_name.lower() != 'content-length':  # 不添加Content-Length，将根据实际内容计算
                    request_text += f"{header_name}: {header_value}\r\n"

            # 添加请求体
            request_body = ""
            content_type = headers.get('Content-Type', '')

            if 'application/json' in content_type:
                new_body_params = body_params.copy()
                if isinstance(new_body_params.get(param_name), list):
                    new_body_params[param_name][0] = param_value
                else:
                    new_body_params[param_name] = param_value
                request_body = json.dumps(new_body_params)
            elif 'application/x-www-form-urlencoded' in content_type:
                new_body_params = body_params.copy()
                if isinstance(new_body_params.get(param_name), list):
                    new_body_params[param_name][0] = param_value
                else:
                    new_body_params[param_name] = param_value

                form_data = {}
                for k, v in new_body_params.items():
                    form_data[k] = v[0] if isinstance(v, list) and v else v
                request_body = urlencode(form_data)
            elif 'multipart/form-data' in content_type:
                boundary = '----WebKitFormBoundary' + ''.join(
                    random.choices(string.ascii_letters + string.digits, k=16))
                request_text = request_text.replace('Content-Type: ' + content_type,
                                                    f'Content-Type: multipart/form-data; boundary={boundary}')

                for k, v in body_params.items():
                    value = v[0] if isinstance(v, list) and v else v
                    if k == param_name:
                        value = param_value

                    request_body += f'--{boundary}\r\n'
                    request_body += f'Content-Disposition: form-data; name="{k}"\r\n\r\n'
                    request_body += f'{value}\r\n'

                request_body += f'--{boundary}--\r\n'

            # 添加Content-Length和请求体
            if request_body:
                request_text += f"Content-Length: {len(request_body)}\r\n"
                request_text += "\r\n"
                request_text += request_body
            else:
                request_text += "\r\n"
        else:
            request_text = f"GET {url} HTTP/1.1\r\n"
            request_text += f"Host: {urlparse(url).netloc}\r\n"
            request_text += "User-Agent: Mozilla/5.0\r\n"
            request_text += "Accept: */*\r\n"
            request_text += "\r\n"

        return request_text