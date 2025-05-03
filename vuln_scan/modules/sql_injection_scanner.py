# vuln_scan/modules/sql_injection_scanner.py
import re
import json
import asyncio
import aiohttp
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from asgiref.sync import sync_to_async
from django.utils import timezone
from rules.models import VulnScanRule


class SqlInjectionScanner:
    """
    SQL注入扫描模块：负责检测SQL注入漏洞
    """

    def __init__(self):
        """初始化扫描器"""
        # 记录已扫描的URL，避免重复扫描
        self.scanned_urls = set()

        # 记录已发现的漏洞，避免重复报告
        self.found_vulnerabilities = set()

        # 默认超时时间
        self.timeout = 10

        # 默认延时时间(用于基于时间的盲注)
        self.time_delay = 5

        # 永久禁用的HTTP头 - 不管数据库规则如何，这些头一定不会被测试
        self.permanently_disabled_headers = ["User-Agent", "Referer"]

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
                return value.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
            except Exception:
                return "[编码错误]"

        # 处理其他类型
        try:
            return str(value)
        except Exception:
            return "[无法转换为字符串]"

    async def scan(self, context):
        """
        执行SQL注入扫描

        参数:
            context: 扫描上下文，包含当前请求信息、配置等

        返回:
            漏洞检测结果列表
        """
        # 获取上下文数据
        asset = context['asset']
        url = context['url']
        method = context['method']
        req_headers = context['req_headers']
        req_content = context['req_content']
        resp_headers = context['resp_headers']
        resp_content = context['resp_content']
        channel_layer = context['channel_layer']

        # 如果URL已扫描，则跳过
        if url in self.scanned_urls:
            return []

        # 标记为已扫描
        self.scanned_urls.add(url)

        # 获取扫描配置
        error_based_payloads = await self.get_error_based_payloads(context)
        blind_payloads = await self.get_blind_payloads(context)
        http_headers = await self.get_http_headers_to_test(context)
        error_patterns = await self.get_error_patterns(context)

        # 检查是否有规则可用
        if not error_based_payloads and not blind_payloads:
            print("警告: 没有可用的SQL注入载荷规则，跳过SQL注入扫描")
            return []

        results = []

        # 1. 检查URL参数中的SQL注入
        if '?' in url:
            url_results = await self.scan_url_parameters(
                context,
                url,
                error_based_payloads,
                blind_payloads,
                error_patterns
            )
            results.extend(url_results)

        # 2. 检查POST请求中的SQL注入
        if method == 'POST' and req_content:
            post_results = await self.scan_post_parameters(
                context,
                url,
                req_content,
                error_based_payloads,
                blind_payloads,
                error_patterns
            )
            results.extend(post_results)

        # 3. 检查HTTP头中的SQL注入
        if http_headers and len(http_headers) > 0:
            header_results = await self.scan_http_headers(
                context,
                url,
                req_headers,
                http_headers,
                error_based_payloads,
                blind_payloads,
                error_patterns
            )
            results.extend(header_results)

        return results

    @sync_to_async
    def _get_rule_from_db(self, vuln_type, subtype):
        """从数据库获取规则"""
        try:
            # 获取指定类型和子类型的漏洞扫描规则
            rules = VulnScanRule.objects.filter(
                vuln_type=vuln_type,
                is_enabled=True
            )

            # 遍历规则找到匹配的子类型
            for rule in rules:
                try:
                    rule_content = json.loads(rule.rule_content)
                    if rule_content.get('subType') == subtype:
                        return rule_content
                except (json.JSONDecodeError, AttributeError):
                    # 如果JSON解析失败，检查rule_content中是否包含子类型标识
                    if f'"subType": "{subtype}"' in rule.rule_content or f'"subType":"{subtype}"' in rule.rule_content:
                        try:
                            # 尝试重新解析，如果失败则返回默认值
                            return json.loads(rule.rule_content)
                        except:
                            pass

            # 如果没有找到匹配的规则，返回None
            return None
        except Exception as e:
            print(f"从数据库获取规则时出错: {str(e)}")
            return None

    async def get_error_based_payloads(self, context):
        """获取回显型SQL注入测试载荷"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('sql_injection', 'error_based')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            return rule_content['payloads']

        # 如果没有找到规则，返回空列表，而不是默认值
        print("未找到回显型SQL注入规则，跳过此类检测")
        return []

    async def get_blind_payloads(self, context):
        """获取盲注型SQL注入测试载荷"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('sql_injection', 'blind')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            return rule_content['payloads']

        # 如果没有找到规则，返回空列表，而不是默认值
        print("未找到盲注型SQL注入规则，跳过此类检测")
        return []

    async def get_http_headers_to_test(self, context):
        """获取要测试的HTTP头列表"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('sql_injection', 'http_header')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            # 从规则中获取要测试的HTTP头列表
            headers = rule_content['payloads']

            # 永久排除指定的头部
            headers = [h for h in headers if h not in self.permanently_disabled_headers]

            return headers

        # 如果没有找到规则，返回空列表，而不是默认值
        print("未找到HTTP头注入规则，跳过此类检测")
        return []

    async def get_error_patterns(self, context):
        """获取SQL错误匹配模式"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('sql_injection', 'error_pattern')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            return rule_content['payloads']

        # 如果没有找到规则，返回空列表，而不是默认值
        print("未找到SQL错误匹配模式规则，使用简化匹配")
        return [
            r"SQL syntax.*error",
            r"MySQL.*error",
            r"ORA-[0-9]",
            r"SQL Server.*error",
            r"PostgreSQL.*error"
        ]

    async def scan_url_parameters(self, context, url, error_payloads, blind_payloads, error_patterns):
        """扫描URL参数中的SQL注入漏洞"""
        results = []

        # 如果没有载荷，直接返回
        if not error_payloads and not blind_payloads:
            return results

        try:
            # 解析URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # 如果没有参数，直接返回
            if not query_params:
                return results

            # 测试每个参数
            for param, values in query_params.items():
                if not values:
                    continue

                original_value = values[0]

                # 测试回显型注入
                for payload in error_payloads:
                    # 创建测试URL
                    test_params = query_params.copy()
                    test_params[param] = [original_value + payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        test_query,
                        parsed_url.fragment
                    ))

                    # 检测是否已存在相同漏洞
                    vuln_key = f"error_based_url_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 发送请求
                    async with aiohttp.ClientSession() as session:
                        try:
                            async with session.get(
                                    test_url,
                                    timeout=self.timeout,
                                    ssl=False
                            ) as response:
                                response_text = await response.text(errors='replace')

                                # 检查是否有SQL错误信息
                                if self.check_sql_error(response_text, error_patterns):
                                    # 记录漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 创建漏洞结果
                                    result = {
                                        'vuln_type': 'sql_injection',
                                        'vuln_subtype': 'error_based',
                                        'name': f'URL参数 {param} 中的SQL注入漏洞',
                                        'description': f'在URL参数 {param} 中发现回显型SQL注入漏洞',
                                        'severity': 'high',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'request': f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}",
                                        'response': f"HTTP/1.1 {response.status} {response.reason}\n{response_text[:500]}...",
                                        'proof': f"在参数 {param} 中注入 {payload} 后，响应中包含SQL错误信息"
                                    }

                                    results.append(result)

                                    # 一旦找到一个参数的漏洞，就不再测试该参数的其他载荷
                                    break
                        except Exception as e:
                            print(f"测试URL参数 {param} 时出错: {str(e)}")
                            continue

                # 测试盲注型注入
                for payload in blind_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"blind_url_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建测试URL
                    test_params = query_params.copy()
                    test_params[param] = [original_value + payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        test_query,
                        parsed_url.fragment
                    ))

                    # 开始时间
                    start_time = asyncio.get_event_loop().time()

                    # 发送请求
                    async with aiohttp.ClientSession() as session:
                        try:
                            async with session.get(
                                    test_url,
                                    timeout=self.timeout * 2,  # 增加超时时间以容纳延时
                                    ssl=False
                            ) as response:
                                # 忽略响应内容，只关注时间
                                _ = await response.text(errors='replace')

                                # 计算响应时间
                                end_time = asyncio.get_event_loop().time()
                                response_time = end_time - start_time

                                # 如果响应时间超过预期延时，可能存在基于时间的盲注
                                if response_time >= self.time_delay * 0.8:
                                    # 记录漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 创建漏洞结果
                                    result = {
                                        'vuln_type': 'sql_injection',
                                        'vuln_subtype': 'blind',
                                        'name': f'URL参数 {param} 中的盲注型SQL注入漏洞',
                                        'description': f'在URL参数 {param} 中发现基于时间的盲注型SQL注入漏洞',
                                        'severity': 'high',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'request': f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}",
                                        'response': f"HTTP/1.1 {response.status} {response.reason}\n响应时间: {response_time}秒",
                                        'proof': f"在参数 {param} 中注入 {payload} 后，响应时间达到 {response_time} 秒，超过了预期的 {self.time_delay} 秒"
                                    }

                                    results.append(result)

                                    # 一旦找到一个参数的漏洞，就不再测试该参数的其他载荷
                                    break
                        except asyncio.TimeoutError:
                            # 超时也可能是基于时间的盲注的证据
                            # 记录漏洞
                            self.found_vulnerabilities.add(vuln_key)

                            # 创建漏洞结果
                            result = {
                                'vuln_type': 'sql_injection',
                                'vuln_subtype': 'blind',
                                'name': f'URL参数 {param} 中的盲注型SQL注入漏洞',
                                'description': f'在URL参数 {param} 中发现基于时间的盲注型SQL注入漏洞',
                                'severity': 'high',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'request': f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}",
                                'response': f"请求超时",
                                'proof': f"在参数 {param} 中注入 {payload} 后，请求超时，可能表明存在基于时间的盲注"
                            }

                            results.append(result)

                            # 一旦找到一个参数的漏洞，就不再测试该参数的其他载荷
                            break
                        except Exception as e:
                            print(f"测试URL参数 {param} 时出错: {str(e)}")
                            continue

        except Exception as e:
            print(f"扫描URL参数时出错: {str(e)}")

        return results

    async def scan_post_parameters(self, context, url, req_content, error_payloads, blind_payloads, error_patterns):
        """扫描POST请求参数中的SQL注入漏洞"""
        results = []

        # 如果没有载荷，直接返回
        if not error_payloads and not blind_payloads:
            return results

        try:
            # 解析POST内容
            content_type = context.get('req_headers', {}).get('Content-Type', '')
            post_params = {}

            if 'application/x-www-form-urlencoded' in content_type:
                # 解析表单数据
                post_params = parse_qs(req_content)
            elif 'application/json' in content_type:
                # 解析JSON数据
                try:
                    import json
                    post_params = json.loads(req_content)
                except:
                    return results
            else:
                # 不支持的内容类型
                return results

            # 如果没有参数，直接返回
            if not post_params:
                return results

            # 解析URL获取主机信息
            parsed_url = urlparse(url)

            # 测试每个参数
            # 这里简化处理，仅支持一级参数
            for param, values in post_params.items():
                if not values:
                    continue

                if isinstance(values, list):
                    original_value = values[0]
                else:
                    original_value = values

                # 将原始值转为字符串
                if not isinstance(original_value, str):
                    original_value = str(original_value)

                # 测试回显型注入
                for payload in error_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"error_based_post_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建测试数据
                    test_params = post_params.copy()
                    if isinstance(test_params[param], list):
                        test_params[param] = [original_value + payload]
                    else:
                        test_params[param] = original_value + payload

                    if 'application/x-www-form-urlencoded' in content_type:
                        test_data = urlencode(test_params, doseq=True)
                        test_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                    else:
                        import json
                        test_data = json.dumps(test_params)
                        test_headers = {'Content-Type': 'application/json'}

                    # 发送请求
                    async with aiohttp.ClientSession() as session:
                        try:
                            async with session.post(
                                    url,
                                    data=test_data,
                                    headers=test_headers,
                                    timeout=self.timeout,
                                    ssl=False
                            ) as response:
                                response_text = await response.text(errors='replace')

                                # 检查是否有SQL错误信息
                                if self.check_sql_error(response_text, error_patterns):
                                    # 记录漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 创建漏洞结果
                                    result = {
                                        'vuln_type': 'sql_injection',
                                        'vuln_subtype': 'error_based',
                                        'name': f'POST参数 {param} 中的SQL注入漏洞',
                                        'description': f'在POST参数 {param} 中发现回显型SQL注入漏洞',
                                        'severity': 'high',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'request': f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {content_type}\n\n{test_data}",
                                        'response': f"HTTP/1.1 {response.status} {response.reason}\n{response_text[:500]}...",
                                        'proof': f"在POST参数 {param} 中注入 {payload} 后，响应中包含SQL错误信息"
                                    }

                                    results.append(result)

                                    # 一旦找到一个参数的漏洞，就不再测试该参数的其他载荷
                                    break
                        except Exception as e:
                            print(f"测试POST参数 {param} 时出错: {str(e)}")
                            continue

                # 测试盲注型注入
                for payload in blind_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"blind_post_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建测试数据
                    test_params = post_params.copy()
                    if isinstance(test_params[param], list):
                        test_params[param] = [original_value + payload]
                    else:
                        test_params[param] = original_value + payload

                    if 'application/x-www-form-urlencoded' in content_type:
                        test_data = urlencode(test_params, doseq=True)
                        test_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                    else:
                        import json
                        test_data = json.dumps(test_params)
                        test_headers = {'Content-Type': 'application/json'}

                    # 开始时间
                    start_time = asyncio.get_event_loop().time()

                    # 发送请求
                    async with aiohttp.ClientSession() as session:
                        try:
                            async with session.post(
                                    url,
                                    data=test_data,
                                    headers=test_headers,
                                    timeout=self.timeout * 2,  # 增加超时时间以容纳延时
                                    ssl=False
                            ) as response:
                                # 忽略响应内容，只关注时间
                                _ = await response.text(errors='replace')

                                # 计算响应时间
                                end_time = asyncio.get_event_loop().time()
                                response_time = end_time - start_time

                                # 如果响应时间超过预期延时，可能存在基于时间的盲注
                                if response_time >= self.time_delay * 0.8:
                                    # 记录漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 创建漏洞结果
                                    result = {
                                        'vuln_type': 'sql_injection',
                                        'vuln_subtype': 'blind',
                                        'name': f'POST参数 {param} 中的盲注型SQL注入漏洞',
                                        'description': f'在POST参数 {param} 中发现基于时间的盲注型SQL注入漏洞',
                                        'severity': 'high',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'request': f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {content_type}\n\n{test_data}",
                                        'response': f"HTTP/1.1 {response.status} {response.reason}\n响应时间: {response_time}秒",
                                        'proof': f"在POST参数 {param} 中注入 {payload} 后，响应时间达到 {response_time} 秒，超过了预期的 {self.time_delay} 秒"
                                    }

                                    results.append(result)

                                    # 一旦找到一个参数的漏洞，就不再测试该参数的其他载荷
                                    break
                        except asyncio.TimeoutError:
                            # 超时也可能是基于时间的盲注的证据
                            # 记录漏洞
                            self.found_vulnerabilities.add(vuln_key)

                            # 创建漏洞结果
                            result = {
                                'vuln_type': 'sql_injection',
                                'vuln_subtype': 'blind',
                                'name': f'POST参数 {param} 中的盲注型SQL注入漏洞',
                                'description': f'在POST参数 {param} 中发现基于时间的盲注型SQL注入漏洞',
                                'severity': 'high',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'request': f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {content_type}\n\n{test_data}",
                                'response': f"请求超时",
                                'proof': f"在POST参数 {param} 中注入 {payload} 后，请求超时，可能表明存在基于时间的盲注"
                            }

                            results.append(result)

                            # 一旦找到一个参数的漏洞，就不再测试该参数的其他载荷
                            break
                        except Exception as e:
                            print(f"测试POST参数 {param} 时出错: {str(e)}")
                            continue

        except Exception as e:
            print(f"扫描POST参数时出错: {str(e)}")

        return results

    async def scan_http_headers(self, context, url, req_headers, headers_to_test, error_payloads, blind_payloads,
                                error_patterns):
        """扫描HTTP头中的SQL注入漏洞"""
        results = []

        # 如果没有载荷，直接返回
        if not error_payloads and not blind_payloads:
            return results

        try:
            # 解析URL获取主机信息
            parsed_url = urlparse(url)

            # 再次过滤永久禁用的头部
            filtered_headers = [h for h in headers_to_test if h not in self.permanently_disabled_headers]

            # 如果没有要测试的头部，直接返回
            if not filtered_headers:
                return results

            print(f"测试HTTP头: {filtered_headers}")

            # 测试每个HTTP头
            for header in filtered_headers:
                # 如果请求中不包含该头部，跳过
                if header not in req_headers:
                    continue

                try:
                    # 安全获取原始值，处理可能的编码问题
                    original_value = self.safe_decode(req_headers[header])

                    # 如果值为空或只有占位符，跳过
                    if not original_value or original_value in ["[二进制数据]", "[编码错误]", "[无法转换为字符串]"]:
                        print(f"跳过HTTP头 {header} 因为值无法正确解码")
                        continue

                    # 测试回显型注入
                    for payload in error_payloads:
                        # 检测是否已存在相同漏洞
                        vuln_key = f"error_based_header_{header}_{url}"
                        if vuln_key in self.found_vulnerabilities:
                            continue

                        # 创建测试头部
                        test_headers = {}
                        for k, v in req_headers.items():
                            if k != header and k not in self.permanently_disabled_headers:
                                # 对其他头部使用安全解码
                                test_headers[k] = self.safe_decode(v)
                            elif k == header:
                                # 对目标头部添加payload
                                test_headers[k] = original_value + payload

                        # 确保Host头存在
                        if 'Host' not in test_headers:
                            test_headers['Host'] = parsed_url.netloc

                        # 发送请求
                        async with aiohttp.ClientSession() as session:
                            try:
                                async with session.get(
                                        url,
                                        headers=test_headers,
                                        timeout=self.timeout,
                                        ssl=False
                                ) as response:
                                    response_text = await response.text(errors='replace')

                                    # 检查是否有SQL错误信息
                                    if self.check_sql_error(response_text, error_patterns):
                                        # 记录漏洞
                                        self.found_vulnerabilities.add(vuln_key)

                                        # 创建漏洞结果
                                        result = {
                                            'vuln_type': 'sql_injection',
                                            'vuln_subtype': 'error_based',
                                            'name': f'HTTP头 {header} 中的SQL注入漏洞',
                                            'description': f'在HTTP头 {header} 中发现回显型SQL注入漏洞',
                                            'severity': 'high',
                                            'url': url,
                                            'parameter': header,
                                            'payload': payload,
                                            'request': f"GET {url} HTTP/1.1\nHost: {parsed_url.netloc}\n{header}: {test_headers[header]}",
                                            'response': f"HTTP/1.1 {response.status} {response.reason}\n{response_text[:500]}...",
                                            'proof': f"在HTTP头 {header} 中注入 {payload} 后，响应中包含SQL错误信息"
                                        }

                                        results.append(result)

                                        # 一旦找到一个头部的漏洞，就不再测试该头部的其他载荷
                                        break
                            except Exception as e:
                                print(f"测试HTTP头 {header} 时出错: {str(e)}")
                                continue

                    # 测试盲注型注入
                    for payload in blind_payloads:
                        # 检测是否已存在相同漏洞
                        vuln_key = f"blind_header_{header}_{url}"
                        if vuln_key in self.found_vulnerabilities:
                            continue

                        # 创建测试头部
                        test_headers = {}
                        for k, v in req_headers.items():
                            if k != header and k not in self.permanently_disabled_headers:
                                # 对其他头部使用安全解码
                                test_headers[k] = self.safe_decode(v)
                            elif k == header:
                                # 对目标头部添加payload
                                test_headers[k] = original_value + payload

                        # 确保Host头存在
                        if 'Host' not in test_headers:
                            test_headers['Host'] = parsed_url.netloc

                        # 开始时间
                        start_time = asyncio.get_event_loop().time()

                        # 发送请求
                        async with aiohttp.ClientSession() as session:
                            try:
                                async with session.get(
                                        url,
                                        headers=test_headers,
                                        timeout=self.timeout * 2,  # 增加超时时间以容纳延时
                                        ssl=False
                                ) as response:
                                    # 忽略响应内容，只关注时间
                                    _ = await response.text(errors='replace')

                                    # 计算响应时间
                                    end_time = asyncio.get_event_loop().time()
                                    response_time = end_time - start_time

                                    # 如果响应时间超过预期延时，可能存在基于时间的盲注
                                    if response_time >= self.time_delay * 0.8:
                                        # 记录漏洞
                                        self.found_vulnerabilities.add(vuln_key)

                                        # 创建漏洞结果
                                        result = {
                                            'vuln_type': 'sql_injection',
                                            'vuln_subtype': 'blind',
                                            'name': f'HTTP头 {header} 中的盲注型SQL注入漏洞',
                                            'description': f'在HTTP头 {header} 中发现基于时间的盲注型SQL注入漏洞',
                                            'severity': 'high',
                                            'url': url,
                                            'parameter': header,
                                            'payload': payload,
                                            'request': f"GET {url} HTTP/1.1\nHost: {parsed_url.netloc}\n{header}: {test_headers[header]}",
                                            'response': f"HTTP/1.1 {response.status} {response.reason}\n响应时间: {response_time}秒",
                                            'proof': f"在HTTP头 {header} 中注入 {payload} 后，响应时间达到 {response_time} 秒，超过了预期的 {self.time_delay} 秒"
                                        }

                                        results.append(result)

                                        # 一旦找到一个头部的漏洞，就不再测试该头部的其他载荷
                                        break
                            except asyncio.TimeoutError:
                                # 超时也可能是基于时间的盲注的证据
                                # 记录漏洞
                                self.found_vulnerabilities.add(vuln_key)

                                # 创建漏洞结果
                                result = {
                                    'vuln_type': 'sql_injection',
                                    'vuln_subtype': 'blind',
                                    'name': f'HTTP头 {header} 中的盲注型SQL注入漏洞',
                                    'description': f'在HTTP头 {header} 中发现基于时间的盲注型SQL注入漏洞',
                                    'severity': 'high',
                                    'url': url,
                                    'parameter': header,
                                    'payload': payload,
                                    'request': f"GET {url} HTTP/1.1\nHost: {parsed_url.netloc}\n{header}: {test_headers[header]}",
                                    'response': f"请求超时",
                                    'proof': f"在HTTP头 {header} 中注入 {payload} 后，请求超时，可能表明存在基于时间的盲注"
                                }

                                results.append(result)

                                # 一旦找到一个头部的漏洞，就不再测试该头部的其他载荷
                                break
                            except Exception as e:
                                print(f"测试HTTP头 {header} 时出错: {str(e)}")
                                continue
                except Exception as e:
                    print(f"处理HTTP头 {header} 时发生未捕获的异常: {str(e)}")
                    continue  # 跳过此头部

        except Exception as e:
            print(f"扫描HTTP头时发生未捕获的异常: {str(e)}")
            import traceback
            traceback.print_exc()

        return results

    def check_sql_error(self, response_text, error_patterns=None):
        """
        检查响应中是否包含SQL错误信息

        参数:
            response_text: 响应文本
            error_patterns: 错误模式列表，如果为None则不检查
        """
        if not response_text:
            return False

        # 如果没有提供错误模式，无法检查
        if not error_patterns:
            print("警告: check_sql_error被调用时没有提供错误模式")
            return False

        # 编译正则表达式以提高性能
        compiled_patterns = []
        for pattern in error_patterns:
            try:
                compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
            except Exception as e:
                print(f"编译正则表达式 '{pattern}' 时出错: {str(e)}")
                continue

        # 如果没有编译成功的模式，无法检查
        if not compiled_patterns:
            return False

        # 检查响应是否包含任何SQL错误信息
        for pattern in compiled_patterns:
            if pattern.search(response_text):
                return True

        return False

    def clear_cache(self):
        """清除缓存"""
        self.scanned_urls.clear()
        self.found_vulnerabilities.clear()
        print("SQL注入扫描器缓存已清除")