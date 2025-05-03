# vuln_scan/modules/command_injection_scanner.py
import asyncio
import re
import json
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import aiohttp
from bs4 import BeautifulSoup
from asgiref.sync import sync_to_async


class CommandInjectionScanner:
    """
    命令注入扫描器：用于检测系统命令注入、盲命令注入和代码注入漏洞
    """

    def __init__(self):
        """初始化扫描器"""
        self.os_command_payloads = []  # 系统命令注入的载荷
        self.blind_command_payloads = []  # 盲命令注入的载荷
        self.code_injection_payloads = []  # 代码注入的载荷
        self.match_patterns = {}  # 匹配模式

        # 已扫描的参数缓存，避免重复扫描
        self.scanned_params = set()

        # 超时设置
        self.request_timeout = 10  # 请求超时时间(秒)
        self.blind_timeout = 3  # 盲注检测的基准超时时间(秒)

    async def scan(self, context):
        """
        扫描命令注入漏洞

        参数:
            context: 扫描上下文，包含请求和响应信息

        返回:
            list: 漏洞结果列表
        """
        try:
            # 提取上下文信息
            asset = context['asset']
            url = context['url']
            method = context['method']
            req_headers = context['req_headers']
            req_content = context['req_content']
            resp_headers = context['resp_headers']
            resp_content = context['resp_content']
            use_proxy = context.get('use_proxy', False)
            proxy_address = context.get('proxy_address', None)
            scan_timeout = context.get('scan_timeout', 30)

            # 加载规则
            await self.load_command_injection_rules()

            # 如果规则未加载，返回空结果
            if not self.os_command_payloads and not self.blind_command_payloads and not self.code_injection_payloads:
                print("未加载命令注入规则，跳过扫描")
                return []

            # 提取URL中的参数并检查
            url_params = self.extract_url_params(url)

            # 提取表单中的参数并检查
            form_params = self.extract_form_params(method, req_content)

            # 提取JSON中的参数并检查
            json_params = self.extract_json_params(req_content)

            # 提取Cookie中的参数并检查
            cookie_params = self.extract_cookie_params(req_headers)

            # 提取HTTP头中的参数并检查
            header_params = self.extract_header_params(req_headers)

            # 合并所有参数
            all_params = {}
            all_params.update(url_params)
            all_params.update(form_params)
            all_params.update(json_params)
            all_params.update(cookie_params)
            all_params.update(header_params)

            # 没有发现参数，跳过
            if not all_params:
                print(f"URL {url} 没有发现可测试的参数，跳过")
                return []

            # 创建HTTP会话
            async with aiohttp.ClientSession() as session:
                # 配置代理
                proxy = proxy_address if use_proxy else None

                # 漏洞结果列表
                vuln_results = []

                # 设置请求超时
                self.request_timeout = scan_timeout

                # 计算基准响应时间
                baseline_time = await self.measure_baseline_response_time(session, url, method, req_headers,
                                                                          req_content, proxy)
                print(f"URL {url} 基准响应时间: {baseline_time:.2f}秒")

                # 根据基准响应时间调整盲注超时时间
                self.blind_timeout = max(3, baseline_time * 3)  # 至少3秒，或基准时间的3倍

                # 扫描每个参数
                for param_type, params in [
                    ('URL', url_params),
                    ('FORM', form_params),
                    ('JSON', json_params),
                    ('COOKIE', cookie_params),
                    ('HEADER', header_params)
                ]:
                    for param_name, param_value in params.items():
                        # 跳过已扫描的参数
                        param_key = f"{url}|{param_type}|{param_name}"
                        if param_key in self.scanned_params:
                            continue

                        # 添加到已扫描集合
                        self.scanned_params.add(param_key)

                        print(f"测试参数: {param_type} - {param_name}")

                        # 1. 测试系统命令注入
                        if self.os_command_payloads:
                            os_cmd_results = await self.test_os_command_injection(
                                session, url, method, req_headers, req_content,
                                param_type, param_name, param_value, proxy
                            )
                            vuln_results.extend(os_cmd_results)

                            # 如果已经发现系统命令注入漏洞，跳过其他测试
                            if os_cmd_results:
                                continue

                        # 2. 测试盲命令注入
                        if self.blind_command_payloads:
                            blind_cmd_results = await self.test_blind_command_injection(
                                session, url, method, req_headers, req_content,
                                param_type, param_name, param_value, proxy, baseline_time
                            )
                            vuln_results.extend(blind_cmd_results)

                            # 如果已经发现盲命令注入漏洞，跳过其他测试
                            if blind_cmd_results:
                                continue

                        # 3. 测试代码注入
                        if self.code_injection_payloads:
                            code_inj_results = await self.test_code_injection(
                                session, url, method, req_headers, req_content,
                                param_type, param_name, param_value, proxy
                            )
                            vuln_results.extend(code_inj_results)

                # 准备漏洞结果
                results = []
                for vuln in vuln_results:
                    vuln_result = {
                        'asset': asset,
                        'vuln_type': 'command_injection',
                        'vuln_subtype': vuln['vuln_subtype'],
                        'name': vuln['name'],
                        'description': vuln['description'],
                        'severity': 'high',  # 命令注入默认为高危
                        'url': vuln['url'],
                        'request': vuln.get('request', ''),
                        'response': vuln.get('response', ''),
                        'proof': vuln['proof'],
                        'parameter': vuln['parameter'],
                        'payload': vuln['payload']
                    }
                    results.append(vuln_result)

                return results

        except Exception as e:
            import traceback
            print(f"命令注入扫描出错: {str(e)}")
            traceback.print_exc()
            return []

    async def load_command_injection_rules(self):
        """从数据库加载命令注入规则"""
        from rules.models import VulnScanRule
        from django.db.models import Q

        # 使用异步方式查询数据库
        vulnScanRules = await sync_to_async(list)(
            VulnScanRule.objects.filter(
                vuln_type='command_injection',
                is_enabled=True
            )
        )

        # 清空现有规则
        self.os_command_payloads = []
        self.blind_command_payloads = []
        self.code_injection_payloads = []
        self.match_patterns = {}

        # 解析规则
        for rule in vulnScanRules:
            try:
                rule_content = json.loads(rule.rule_content)
                sub_type = rule_content.get('subType', '')

                if sub_type == 'os_command' and 'payloads' in rule_content:
                    self.os_command_payloads = rule_content['payloads']

                elif sub_type == 'blind_os_command' and 'payloads' in rule_content:
                    self.blind_command_payloads = rule_content['payloads']

                elif sub_type == 'code_injection' and 'payloads' in rule_content:
                    self.code_injection_payloads = rule_content['payloads']

                elif sub_type == 'match_patterns' and 'patterns' in rule_content:
                    self.match_patterns = rule_content['patterns']

            except Exception as e:
                print(f"解析命令注入规则失败 (ID: {rule.id}): {str(e)}")

        # 打印加载的规则数量
        print(f"已加载 {len(self.os_command_payloads)} 条系统命令注入载荷")
        print(f"已加载 {len(self.blind_command_payloads)} 条盲命令注入载荷")
        print(f"已加载 {len(self.code_injection_payloads)} 条代码注入载荷")
        print(f"已加载 {sum(len(patterns) for patterns in self.match_patterns.values())} 条匹配模式")

    def clear_cache(self):
        """清除缓存"""
        self.scanned_params.clear()
        print("命令注入扫描器缓存已清除")

    # 参数提取方法
    def extract_url_params(self, url):
        """提取URL中的参数"""
        try:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)

            # 转换为简单的字典格式，每个参数只取第一个值
            return {key: values[0] for key, values in params.items()}
        except:
            return {}

    def extract_form_params(self, method, req_content):
        """提取表单中的参数"""
        params = {}

        try:
            if method.upper() == 'POST' and req_content:
                # 尝试解析为表单数据
                if 'application/x-www-form-urlencoded' in req_content:
                    # 找到请求体部分
                    body = req_content.split('\r\n\r\n', 1)[-1]

                    # 解析参数
                    form_params = parse_qs(body)
                    params = {key: values[0] for key, values in form_params.items()}
        except:
            pass

        return params

    def extract_json_params(self, req_content):
        """提取JSON中的参数"""
        params = {}

        try:
            if req_content and 'application/json' in req_content:
                # 找到请求体JSON部分
                body = req_content.split('\r\n\r\n', 1)[-1]

                # 解析JSON
                json_data = json.loads(body)

                # 扁平化JSON对象为参数字典
                params = self.flatten_json(json_data)
        except:
            pass

        return params

    def extract_cookie_params(self, req_headers):
        """提取Cookie中的参数"""
        params = {}

        try:
            # 从请求头中查找Cookie
            cookie_header = None
            headers_lines = req_headers.split('\r\n')

            for line in headers_lines:
                if line.lower().startswith('cookie:'):
                    cookie_header = line[7:].strip()
                    break

            if cookie_header:
                # 解析Cookie
                cookie_parts = cookie_header.split(';')
                for part in cookie_parts:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        params[key.strip()] = value.strip()
        except:
            pass

        return params

    def extract_header_params(self, req_headers):
        """提取HTTP头中的参数"""
        params = {}

        try:
            # 从请求头中提取所有头
            headers_lines = req_headers.split('\r\n')

            for line in headers_lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()

                    # 跳过常见的非参数头
                    skip_headers = ['host', 'user-agent', 'accept', 'connection',
                                    'content-type', 'content-length', 'referer']

                    if key.lower() not in skip_headers:
                        params[key] = value.strip()
        except:
            pass

        return params

    def flatten_json(self, json_obj, parent_key=''):
        """将嵌套的JSON对象扁平化为参数字典"""
        params = {}

        if isinstance(json_obj, dict):
            for key, value in json_obj.items():
                new_key = f"{parent_key}.{key}" if parent_key else key

                if isinstance(value, (dict, list)):
                    params.update(self.flatten_json(value, new_key))
                else:
                    params[new_key] = str(value)

        elif isinstance(json_obj, list):
            for i, item in enumerate(json_obj):
                new_key = f"{parent_key}[{i}]"

                if isinstance(item, (dict, list)):
                    params.update(self.flatten_json(item, new_key))
                else:
                    params[new_key] = str(item)

        return params

    # 测试方法
    async def test_os_command_injection(self, session, url, method, req_headers, req_content,
                                        param_type, param_name, param_value, proxy):
        """测试系统命令注入"""
        results = []

        for payload in self.os_command_payloads:
            try:
                # 构造新的参数值
                new_value = f"{param_value}{payload}"

                # 发送请求
                status, response_time, resp_headers, resp_content = await self.send_injection_request(
                    session, url, method, req_headers, req_content,
                    param_type, param_name, new_value, proxy
                )

                # 检查响应中是否包含命令执行的特征
                if self.has_os_command_pattern(resp_content):
                    # 构造请求字符串，用于记录漏洞证明
                    request_str = f"{method} {url}\n{req_headers}\n\n{req_content}"

                    # 找到匹配的模式
                    matched_pattern = self.find_matched_os_command_pattern(resp_content)

                    # 构造漏洞证明
                    proof = f"发现系统命令注入漏洞，参数: {param_name}，载荷: {payload}\n"
                    proof += f"响应包含系统命令执行的特征: {matched_pattern}\n"
                    proof += f"执行结果: {self.extract_command_output(resp_content, matched_pattern)}"

                    # 添加漏洞结果
                    result = {
                        'vuln_subtype': 'os_command',
                        'name': f"系统命令注入漏洞 - {param_name}",
                        'description': f"在参数 '{param_name}' 中存在系统命令注入漏洞，可以利用 '{payload}' 执行系统命令。",
                        'url': url,
                        'request': request_str,
                        'response': resp_content,
                        'proof': proof,
                        'parameter': param_name,
                        'payload': payload
                    }

                    results.append(result)
                    print(f"发现系统命令注入漏洞: {param_name} - {payload}")

                    # 找到一个漏洞后，停止测试此参数
                    break

            except Exception as e:
                print(f"测试系统命令注入时出错: {str(e)}")

        return results

    async def test_blind_command_injection(self, session, url, method, req_headers, req_content,
                                           param_type, param_name, param_value, proxy, baseline_time):
        """测试盲命令注入"""
        results = []

        for payload in self.blind_command_payloads:
            try:
                # 构造新的参数值
                new_value = f"{param_value}{payload}"

                # 发送请求并记录响应时间
                start_time = time.time()
                status, response_time, resp_headers, resp_content = await self.send_injection_request(
                    session, url, method, req_headers, req_content,
                    param_type, param_name, new_value, proxy
                )

                # 确定是否发现时间延迟特征
                time_diff = response_time - baseline_time
                delay_threshold = self.blind_timeout * 0.8  # 如果响应时间增加了至少80%的盲注超时时间

                if time_diff > delay_threshold:
                    # 构造请求字符串，用于记录漏洞证明
                    request_str = f"{method} {url}\n{req_headers}\n\n{req_content}"

                    # 构造漏洞证明
                    proof = f"发现盲命令注入漏洞，参数: {param_name}，载荷: {payload}\n"
                    proof += f"基准响应时间: {baseline_time:.2f}秒，注入后响应时间: {response_time:.2f}秒\n"
                    proof += f"时间差异: {time_diff:.2f}秒，超过阈值 {delay_threshold:.2f}秒"

                    # 添加漏洞结果
                    result = {
                        'vuln_subtype': 'blind_os_command',
                        'name': f"盲命令注入漏洞 - {param_name}",
                        'description': f"在参数 '{param_name}' 中存在盲命令注入漏洞，可以利用 '{payload}' 执行系统命令导致时间延迟。",
                        'url': url,
                        'request': request_str,
                        'response': resp_content,
                        'proof': proof,
                        'parameter': param_name,
                        'payload': payload
                    }

                    results.append(result)
                    print(f"发现盲命令注入漏洞: {param_name} - {payload}")

                    # 找到一个漏洞后，停止测试此参数
                    break

            except Exception as e:
                print(f"测试盲命令注入时出错: {str(e)}")

        return results

    async def test_code_injection(self, session, url, method, req_headers, req_content,
                                  param_type, param_name, param_value, proxy):
        """测试代码注入"""
        results = []

        for payload in self.code_injection_payloads:
            try:
                # 构造新的参数值
                new_value = f"{param_value}{payload}"

                # 发送请求
                status, response_time, resp_headers, resp_content = await self.send_injection_request(
                    session, url, method, req_headers, req_content,
                    param_type, param_name, new_value, proxy
                )

                # 检查响应中是否包含代码执行的特征
                if self.has_code_injection_pattern(resp_content):
                    # 构造请求字符串，用于记录漏洞证明
                    request_str = f"{method} {url}\n{req_headers}\n\n{req_content}"

                    # 找到匹配的模式
                    matched_pattern = self.find_matched_code_pattern(resp_content)

                    # 确定代码类型
                    code_type = self.determine_code_type(payload)

                    # 构造漏洞证明
                    proof = f"发现代码注入漏洞，参数: {param_name}，载荷: {payload}\n"
                    proof += f"代码类型: {code_type}\n"
                    proof += f"响应包含代码执行的特征: {matched_pattern}\n"
                    proof += f"执行结果: {self.extract_command_output(resp_content, matched_pattern)}"

                    # 添加漏洞结果
                    result = {
                        'vuln_subtype': code_type,
                        'name': f"{code_type.replace('_', ' ').title()}注入漏洞 - {param_name}",
                        'description': f"在参数 '{param_name}' 中存在{code_type.replace('_', ' ').title()}代码注入漏洞，可以利用 '{payload}' 执行代码。",
                        'url': url,
                        'request': request_str,
                        'response': resp_content,
                        'proof': proof,
                        'parameter': param_name,
                        'payload': payload
                    }

                    results.append(result)
                    print(f"发现代码注入漏洞: {param_name} - {payload}")

                    # 找到一个漏洞后，停止测试此参数
                    break

            except Exception as e:
                print(f"测试代码注入时出错: {str(e)}")

        return results

    # 辅助方法
    async def send_injection_request(self, session, url, method, req_headers, req_content,
                                     param_type, param_name, new_value, proxy):
        """发送注入请求"""
        try:
            # 准备新的请求
            new_url = url
            new_headers = req_headers
            new_body = req_content

            # 修改不同类型的参数
            if param_type == 'URL':
                # 修改URL参数
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)

                # 更新参数值
                query_params[param_name] = [new_value]

                # 重建查询字符串
                new_query = urlencode(query_params, doseq=True)

                # 重建URL
                new_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))

            elif param_type == 'FORM':
                # 修改表单参数
                if 'application/x-www-form-urlencoded' in req_content:
                    # 分割请求头和请求体
                    parts = req_content.split('\r\n\r\n', 1)
                    if len(parts) > 1:
                        headers_part = parts[0]
                        body_part = parts[1]

                        # 解析表单数据
                        form_params = parse_qs(body_part)

                        # 更新参数值
                        form_params[param_name] = [new_value]

                        # 重建表单数据
                        new_body_part = urlencode(form_params, doseq=True)

                        # 重建请求内容
                        new_body = f"{headers_part}\r\n\r\n{new_body_part}"

            elif param_type == 'JSON':
                # 修改JSON参数
                if 'application/json' in req_content:
                    # 分割请求头和请求体
                    parts = req_content.split('\r\n\r\n', 1)
                    if len(parts) > 1:
                        headers_part = parts[0]
                        body_part = parts[1]

                        try:
                            # 解析JSON数据
                            json_data = json.loads(body_part)

                            # 更新参数值（简单处理，只支持一级参数）
                            json_data[param_name] = new_value

                            # 重建JSON数据
                            new_body_part = json.dumps(json_data)

                            # 重建请求内容
                            new_body = f"{headers_part}\r\n\r\n{new_body_part}"
                        except:
                            # JSON解析失败，尝试简单替换
                            pattern = f'"{param_name}"\\s*:\\s*"[^"]*"'
                            replacement = f'"{param_name}": "{new_value}"'
                            new_body = re.sub(pattern, replacement, req_content)

            elif param_type == 'COOKIE':
                # 修改Cookie参数
                pattern = f'{param_name}=[^;]+'
                replacement = f'{param_name}={new_value}'
                new_headers = re.sub(pattern, replacement, req_headers)

            elif param_type == 'HEADER':
                # 修改HTTP头参数
                pattern = f'{param_name}:.*?(\r\n|\n)'
                replacement = f'{param_name}: {new_value}\r\n'
                new_headers = re.sub(pattern, replacement, req_headers)

            # 发送请求
            if method.upper() == 'GET':
                start_time = time.time()
                async with session.get(new_url,
                                       headers=self.parse_headers(new_headers),
                                       proxy=proxy,
                                       timeout=self.request_timeout,
                                       allow_redirects=True) as response:
                    resp_content = await response.text()
                    response_time = time.time() - start_time
                    return response.status, response_time, str(response.headers), resp_content

            elif method.upper() == 'POST':
                # 获取请求体
                body = new_body.split('\r\n\r\n', 1)[-1] if new_body else ''

                start_time = time.time()
                async with session.post(new_url,
                                        headers=self.parse_headers(new_headers),
                                        data=body,
                                        proxy=proxy,
                                        timeout=self.request_timeout,
                                        allow_redirects=True) as response:
                    resp_content = await response.text()
                    response_time = time.time() - start_time
                    return response.status, response_time, str(response.headers), resp_content

            else:
                # 其他HTTP方法暂不支持
                return 0, 0, '', ''

        except asyncio.TimeoutError:
            # 请求超时，对于盲注测试可能是正常的
            return 0, self.request_timeout, '', ''

        except Exception as e:
            print(f"发送注入请求时出错: {str(e)}")
            return 0, 0, '', ''

    def parse_headers(self, headers_str):
        """解析HTTP头字符串为字典"""
        headers = {}

        if not headers_str:
            return headers

        lines = headers_str.split('\r\n')
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        return headers

    async def measure_baseline_response_time(self, session, url, method, req_headers, req_content, proxy):
        """测量基准响应时间"""
        try:
            # 发送3次请求，取平均值作为基准
            total_time = 0
            valid_count = 0

            for _ in range(3):
                try:
                    if method.upper() == 'GET':
                        start_time = time.time()
                        async with session.get(url,
                                               headers=self.parse_headers(req_headers),
                                               proxy=proxy,
                                               timeout=self.request_timeout) as response:
                            await response.text()
                            response_time = time.time() - start_time
                            total_time += response_time
                            valid_count += 1

                    elif method.upper() == 'POST':
                        # 获取请求体
                        body = req_content.split('\r\n\r\n', 1)[-1] if req_content else ''

                        start_time = time.time()
                        async with session.post(url,
                                                headers=self.parse_headers(req_headers),
                                                data=body,
                                                proxy=proxy,
                                                timeout=self.request_timeout) as response:
                            await response.text()
                            response_time = time.time() - start_time
                            total_time += response_time
                            valid_count += 1

                except:
                    # 忽略错误
                    pass

            # 计算平均响应时间
            if valid_count > 0:
                return total_time / valid_count
            else:
                return 1.0  # 默认1秒

        except Exception as e:
            print(f"测量基准响应时间出错: {str(e)}")
            return 1.0  # 默认1秒

    def has_os_command_pattern(self, response):
        """检查响应中是否包含系统命令执行的特征"""
        if not response or not self.match_patterns:
            return False

        # 获取系统命令匹配模式
        patterns = self.match_patterns.get('os_command', [])

        # 检查响应中是否包含任意一个模式
        for pattern in patterns:
            if pattern in response:
                return True

        return False

    def find_matched_os_command_pattern(self, response):
        """找到匹配的系统命令特征模式"""
        if not response or not self.match_patterns:
            return "未知模式"

        # 获取系统命令匹配模式
        patterns = self.match_patterns.get('os_command', [])

        # 查找第一个匹配的模式
        for pattern in patterns:
            if pattern in response:
                return pattern

        return "未知模式"

    def has_code_injection_pattern(self, response):
        """检查响应中是否包含代码执行的特征"""
        if not response or not self.match_patterns:
            return False

        # 获取代码注入匹配模式
        patterns = self.match_patterns.get('code_injection', [])

        # 检查响应中是否包含任意一个模式
        for pattern in patterns:
            if pattern in response:
                return True

        return False

    def find_matched_code_pattern(self, response):
        """找到匹配的代码执行特征模式"""
        if not response or not self.match_patterns:
            return "未知模式"

        # 获取代码注入匹配模式
        patterns = self.match_patterns.get('code_injection', [])

        # 查找第一个匹配的模式
        for pattern in patterns:
            if pattern in response:
                return pattern

        return "未知模式"

    def determine_code_type(self, payload):
        """根据载荷确定代码类型"""
        if not payload:
            return "code_injection"

        if "<?php" in payload or "system(" in payload:
            return "php_code"
        elif "eval(" in payload and ("print" in payload or "python" in payload):
            return "python_code"
        elif "{{" in payload or "${" in payload:
            return "template_injection"
        elif "<%=" in payload or ".jsp" in payload:
            return "java_code"

        return "code_injection"

    def extract_command_output(self, response, matched_pattern):
        """从响应中提取命令输出"""
        if not response or not matched_pattern:
            return "无法提取输出"

        # 尝试从响应中提取与模式相关的内容
        try:
            # 查找包含模式的行
            lines = response.split('\n')
            for i, line in enumerate(lines):
                if matched_pattern in line:
                    # 返回包含匹配模式的行及其前后几行
                    context_start = max(0, i - 2)
                    context_end = min(len(lines), i + 3)
                    return '\n'.join(lines[context_start:context_end])

            # 如果无法找到明确的上下文，返回模式周围的内容
            pattern_pos = response.find(matched_pattern)
            if pattern_pos >= 0:
                start_pos = max(0, pattern_pos - 50)
                end_pos = min(len(response), pattern_pos + len(matched_pattern) + 50)
                return response[start_pos:end_pos]

        except:
            pass

        return f"找到匹配: {matched_pattern}"