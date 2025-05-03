# vuln_scan/modules/file_inclusion_scanner.py
import json
import re
import aiohttp
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from asgiref.sync import sync_to_async
from rules.models import VulnScanRule


class FileInclusionScanner:
    """
    文件包含扫描器：检测本地文件包含(LFI)和远程文件包含(RFI)漏洞
    """

    def __init__(self):
        """初始化扫描器"""
        self.lfi_payloads = []  # 本地文件包含测试载荷
        self.rfi_payloads = []  # 远程文件包含测试载荷
        self.file_patterns = {}  # 文件内容匹配模式
        self.rules_loaded = False  # 规则是否已加载
        self.rules_last_check = 0  # 上次检查规则的时间
        self.rules_check_interval = 300  # 规则检查间隔（秒）

    def clear_cache(self):
        """清除缓存"""
        self.rules_loaded = False

    async def load_rules(self):
        """
        从数据库加载规则
        如果没有规则，返回False，跳过扫描
        """
        try:
            current_time = asyncio.get_event_loop().time()

            # 如果规则已加载且未超过检查间隔，则跳过
            if self.rules_loaded and (current_time - self.rules_last_check < self.rules_check_interval):
                return True

            # 加载本地文件包含规则
            lfi_rules = await self._get_rules_by_type_and_subtype('file_inclusion', 'lfi')
            if lfi_rules:
                rule_content = json.loads(lfi_rules[0].rule_content)
                self.lfi_payloads = rule_content.get('payloads', [])
                print(f"已加载 {len(self.lfi_payloads)} 条本地文件包含载荷")
            else:
                print("未找到本地文件包含规则，不执行LFI扫描")
                self.lfi_payloads = []

            # 加载远程文件包含规则
            rfi_rules = await self._get_rules_by_type_and_subtype('file_inclusion', 'rfi')
            if rfi_rules:
                rule_content = json.loads(rfi_rules[0].rule_content)
                self.rfi_payloads = rule_content.get('payloads', [])
                print(f"已加载 {len(self.rfi_payloads)} 条远程文件包含载荷")
            else:
                print("未找到远程文件包含规则，不执行RFI扫描")
                self.rfi_payloads = []

            # 加载文件匹配模式规则
            pattern_rules = await self._get_rules_by_type_and_subtype('file_inclusion', 'patterns')
            if pattern_rules:
                rule_content = json.loads(pattern_rules[0].rule_content)
                self.file_patterns = rule_content.get('patterns', {})
                print(f"已加载 {len(self.file_patterns)} 种文件匹配模式")
            else:
                print("未找到文件匹配模式规则，不执行文件内容匹配")
                self.file_patterns = {}

            # 更新规则加载状态
            self.rules_loaded = True
            self.rules_last_check = current_time

            # 如果没有任何规则，返回False
            if not self.lfi_payloads and not self.rfi_payloads:
                print("没有可用的文件包含扫描规则，跳过扫描")
                return False

            return True
        except Exception as e:
            print(f"加载文件包含规则失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    @sync_to_async
    def _get_rules_by_type_and_subtype(self, vuln_type, subtype):
        """获取指定类型和子类型的规则"""
        try:
            rules = []
            # 获取指定类型的规则
            type_rules = VulnScanRule.objects.filter(
                vuln_type=vuln_type,
                is_enabled=True
            )

            # 从规则内容中筛选子类型
            for rule in type_rules:
                try:
                    rule_content = json.loads(rule.rule_content)
                    if rule_content.get('subType') == subtype:
                        rules.append(rule)
                except json.JSONDecodeError:
                    continue  # 跳过无效的JSON
                except Exception as e:
                    print(f"解析规则内容出错: {str(e)}")
                    continue

            return rules
        except Exception as e:
            print(f"获取规则失败: {str(e)}")
            return []

    async def scan(self, context):
        """执行扫描"""
        # 加载规则，如果没有规则则跳过扫描
        rules_loaded = await self.load_rules()
        if not rules_loaded:
            return []

        url = context['url']
        method = context['method']
        req_headers = context['req_headers']
        req_content = context['req_content']
        resp_headers = context['resp_headers']
        resp_content = context['resp_content']
        asset = context['asset']

        # 检查URL, 只对GET和POST请求进行检测
        if method not in ['GET', 'POST']:
            return []

        # 解析URL和参数
        parsed_url = urlparse(url)
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)

        # 检查是否有参数
        if not query_params and method == 'GET':
            return []  # 没有参数，跳过检测

        # 准备结果
        results = []

        # 创建HTTP客户端
        timeout = aiohttp.ClientTimeout(total=context.get('scan_timeout', 10))
        connector = None
        if context.get('use_proxy', False):
            connector = aiohttp.ProxyConnector.from_url(context.get('proxy_address', 'http://localhost:7890'))

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            # 对每个参数进行测试
            for param, values in query_params.items():
                # 检查本地文件包含漏洞
                if self.lfi_payloads:
                    lfi_results = await self.check_lfi(session, url, param, values[0], context)
                    results.extend(lfi_results)

                # 检查远程文件包含漏洞
                if self.rfi_payloads:
                    rfi_results = await self.check_rfi(session, url, param, values[0], context)
                    results.extend(rfi_results)

            # 对POST请求的表单数据进行测试
            if method == 'POST' and 'application/x-www-form-urlencoded' in req_headers.get('Content-Type', ''):
                post_params = parse_qs(req_content)
                for param, values in post_params.items():
                    # 检查本地文件包含漏洞
                    if self.lfi_payloads:
                        lfi_results = await self.check_lfi(session, url, param, values[0], context, method='POST',
                                                           post_data=post_params)
                        results.extend(lfi_results)

                    # 检查远程文件包含漏洞
                    if self.rfi_payloads:
                        rfi_results = await self.check_rfi(session, url, param, values[0], context, method='POST',
                                                           post_data=post_params)
                        results.extend(rfi_results)

        return results

    async def check_lfi(self, session, url, param, orig_value, context, method='GET', post_data=None):
        """检查本地文件包含漏洞"""
        results = []

        # 解析URL
        parsed_url = urlparse(url)

        for payload in self.lfi_payloads:
            try:
                # 构造测试URL
                if method == 'GET':
                    params = parse_qs(parsed_url.query)
                    params[param] = [payload]
                    query = urlencode(params, doseq=True)
                    test_url = urlparse(url)._replace(query=query).geturl()

                    # 发送请求
                    async with session.get(test_url) as response:
                        status = response.status
                        response_text = await response.text()

                else:  # POST
                    test_data = post_data.copy()
                    test_data[param] = [payload]

                    # 发送请求
                    async with session.post(url, data=urlencode(test_data, doseq=True), headers={
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }) as response:
                        status = response.status
                        response_text = await response.text()

                # 检查是否存在文件包含
                lfi_result = self.check_file_content(response_text)
                if lfi_result:
                    file_type, pattern = lfi_result

                    # 构造请求数据
                    if method == 'GET':
                        request_data = f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}\nUser-Agent: Mozilla/5.0"
                    else:
                        request_data = f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: application/x-www-form-urlencoded\n\n{urlencode(test_data, doseq=True)}"

                    # 构造响应数据
                    response_data = f"HTTP/1.1 {status} OK\n\n{response_text[:300]}..."

                    # 添加结果
                    results.append({
                        'vuln_type': 'file_inclusion',
                        'vuln_subtype': 'lfi',
                        'name': '本地文件包含漏洞',
                        'description': f'发现本地文件包含漏洞，可以通过参数"{param}"包含本地文件',
                        'severity': 'high',
                        'url': url if method == 'POST' else test_url,
                        'request': request_data,
                        'response': response_data,
                        'proof': f'通过参数"{param}"传入路径"{payload}"，成功包含本地文件，特征: {pattern}，文件类型: {file_type}',
                        'parameter': param,
                        'payload': payload
                    })

                    # 每个参数只添加一个结果
                    break

            except Exception as e:
                print(f"检查LFI时出错: {str(e)}")
                continue

        return results

    async def check_rfi(self, session, url, param, orig_value, context, method='GET', post_data=None):
        """检查远程文件包含漏洞"""
        results = []

        # 解析URL
        parsed_url = urlparse(url)

        for payload in self.rfi_payloads:
            try:
                # 构造测试URL
                if method == 'GET':
                    params = parse_qs(parsed_url.query)
                    params[param] = [payload]
                    query = urlencode(params, doseq=True)
                    test_url = urlparse(url)._replace(query=query).geturl()

                    # 发送请求
                    async with session.get(test_url) as response:
                        status = response.status
                        response_text = await response.text()

                else:  # POST
                    test_data = post_data.copy()
                    test_data[param] = [payload]

                    # 发送请求
                    async with session.post(url, data=urlencode(test_data, doseq=True), headers={
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }) as response:
                        status = response.status
                        response_text = await response.text()

                # 检查是否存在远程文件包含（简化检测，只检查是否包含远程URL或PHP代码执行标志）
                has_rfi = False

                # 如果有文件包含匹配模式，使用它们
                rfi_pattern_check = self.check_file_content(response_text)
                if rfi_pattern_check:
                    has_rfi = True
                    file_type, pattern = rfi_pattern_check

                # 检查php相关关键字（如果没有匹配到模式）
                if not has_rfi and ('PHP Version' in response_text or
                                    'remote file inclusion' in response_text.lower() or
                                    'shell done' in response_text.lower() or
                                    re.search(r'<\?php|^\s*php>', response_text, re.IGNORECASE)):
                    has_rfi = True
                    file_type = "php_code"
                    pattern = "PHP代码执行"

                if has_rfi:
                    # 构造请求数据
                    if method == 'GET':
                        request_data = f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}\nUser-Agent: Mozilla/5.0"
                    else:
                        request_data = f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: application/x-www-form-urlencoded\n\n{urlencode(test_data, doseq=True)}"

                    # 构造响应数据
                    response_data = f"HTTP/1.1 {status} OK\n\n{response_text[:300]}..."

                    # 添加结果
                    results.append({
                        'vuln_type': 'file_inclusion',
                        'vuln_subtype': 'rfi',
                        'name': '远程文件包含漏洞',
                        'description': f'发现远程文件包含漏洞，可以通过参数"{param}"包含远程文件',
                        'severity': 'high',
                        'url': url if method == 'POST' else test_url,
                        'request': request_data,
                        'response': response_data,
                        'proof': f'通过参数"{param}"传入远程URL"{payload}"，成功包含远程文件，特征: {pattern}',
                        'parameter': param,
                        'payload': payload
                    })

                    # 每个参数只添加一个结果
                    break

            except Exception as e:
                print(f"检查RFI时出错: {str(e)}")
                continue

        return results

    def check_file_content(self, response_text):
        """
        检查响应内容是否包含已知文件的特征

        返回:
            成功匹配时返回 (file_type, pattern)
            未匹配时返回 None
        """
        if not self.file_patterns:
            return None

        for file_type, patterns in self.file_patterns.items():
            for pattern in patterns:
                if pattern in response_text:
                    return (file_type, pattern)

        return None