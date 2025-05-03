# vuln_scan/modules/sql_injection_scanner.py
import re
import asyncio
import aiohttp
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


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

        results = []

        # 1. 检查URL参数中的SQL注入
        if '?' in url:
            url_results = await self.scan_url_parameters(
                context,
                url,
                error_based_payloads,
                blind_payloads
            )
            results.extend(url_results)

        # 2. 检查POST请求中的SQL注入
        if method == 'POST' and req_content:
            post_results = await self.scan_post_parameters(
                context,
                url,
                req_content,
                error_based_payloads,
                blind_payloads
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
                blind_payloads
            )
            results.extend(header_results)

        return results

    async def get_error_based_payloads(self, context):
        """获取回显型SQL注入测试载荷"""
        # 这里实际应该从数据库或配置中获取
        # 现在先使用默认值
        return [
            "'",
            "\"",
            "')",
            "\";",
            "' UNION SELECT 1,2,3--",
            "\" UNION SELECT @@version,2,3--",
            "' OR '1'='1"
        ]

    async def get_blind_payloads(self, context):
        """获取盲注型SQL注入测试载荷"""
        # 这里实际应该从数据库或配置中获取
        # 现在先使用默认值
        return [
            "' OR (SELECT SLEEP(5))--",
            "'; SELECT SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND (SELECT COUNT(*) FROM ALL_USERS t1,ALL_USERS t2)>0--",
            "' AND 1=dbms_pipe.receive_message('RDS',10)--"
        ]

    async def get_http_headers_to_test(self, context):
        """获取要测试的HTTP头列表"""
        # 这里实际应该从数据库或配置中获取
        # 现在先使用默认值
        return [
            "Cookie",
            "X-Forwarded-For",
            "Referer",
            "User-Agent",
            "Authorization"
        ]

    async def scan_url_parameters(self, context, url, error_payloads, blind_payloads):
        """扫描URL参数中的SQL注入漏洞"""
        results = []

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
                                response_text = await response.text()

                                # 检查是否有SQL错误信息
                                if self.check_sql_error(response_text):
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
                    vuln_key = f"blind_url_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

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
                                _ = await response.text()

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

    async def scan_post_parameters(self, context, url, req_content, error_payloads, blind_payloads):
        """扫描POST请求参数中的SQL注入漏洞"""
        results = []

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
                                response_text = await response.text()

                                # 检查是否有SQL错误信息
                                if self.check_sql_error(response_text):
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
                                _ = await response.text()

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

    async def scan_http_headers(self, context, url, req_headers, headers_to_test, error_payloads, blind_payloads):
        """扫描HTTP头中的SQL注入漏洞"""
        results = []

        try:
            # 解析URL获取主机信息
            parsed_url = urlparse(url)

            # 测试每个HTTP头
            for header in headers_to_test:
                # 如果请求中不包含该头部，跳过
                if header not in req_headers:
                    continue

                # 安全获取原始值，处理可能的编码问题
                try:
                    original_value = req_headers[header]

                    # 处理二进制数据或非UTF-8编码的字符串
                    if isinstance(original_value, bytes):
                        original_value = original_value.decode('utf-8', errors='replace')
                    else:
                        # 确保字符串值是有效的UTF-8
                        if isinstance(original_value, str):
                            original_value = original_value.encode('utf-8', errors='replace').decode('utf-8',
                                                                                                     errors='replace')
                        else:
                            # 处理其他类型，如None或非字符串类型
                            original_value = str(original_value)
                except Exception as e:
                    print(f"处理HTTP头 {header} 的值时出错: {str(e)}")
                    continue  # 跳过这个头部

                # 测试回显型注入
                for payload in error_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"error_based_header_{header}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建测试头部
                    test_headers = req_headers.copy()
                    test_headers[header] = original_value + payload

                    # 发送请求
                    async with aiohttp.ClientSession() as session:
                        try:
                            async with session.get(
                                    url,
                                    headers=test_headers,
                                    timeout=self.timeout,
                                    ssl=False
                            ) as response:
                                response_text = await response.text(errors='replace')  # 使用errors='replace'处理响应编码问题

                                # 检查是否有SQL错误信息
                                if self.check_sql_error(response_text):
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
                    test_headers = req_headers.copy()
                    test_headers[header] = original_value + payload

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
                                _ = await response.text(errors='replace')  # 使用errors='replace'处理响应编码问题

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
            print(f"扫描HTTP头时出错: {str(e)}")

        return results

    def check_sql_error(self, response_text):
        """检查响应中是否包含SQL错误信息"""
        # 常见的SQL错误信息模式
        error_patterns = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysqli",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that (corresponds to|fits) your MySQL server version",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc\.exceptions",
            r"SQLite3::query",
            r"SQLite3::exec",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"PLS-[0-9][0-9][0-9][0-9]",
            r"Npgsql\.",
            r"PostgreSQL.*?ERROR",
            r"Warning.*?\Wpg_",
            r"valid PostgreSQL result",
            r"Unclosed quotation mark after the character string",
            r"ODBC SQL Server Driver",
            r"Microsoft SQL Native Client error",
            r"SQLSTATE[",
            r"SQL Server message",
            r"Warning.*?mssql_",
            r"Driver.*? SQL[\-\_\ ]*Server",
            r"JET Database Engine",
            r"Access Database Engine",
            r"ADODB\.Command",
            r"ADODB\.Field error",
            r"Microsoft Access Driver",
            r"ODBC Microsoft Access",
            r"OLE DB.*? 'Microsoft\\.Jet\\.OLEDB",
            r"Microsoft Access",
            r"Syntax error \(missing operator\) in query expression",
            r"ODBC.*?Driver.*?SQL",
            r"DB2 SQL error",
            r"Informix\s+ODBC",
            r"DM_QUERY_E_SYNTAX",
            r"SybSQLException",
            r"Warning.*?ingres_",
            r"Ingres SQLSTATE",
            r"CLI Driver.*?DB2",
            r"SQLiteException",
            r"sqlite3.OperationalError:",
        ]

        # 编译正则表达式以提高性能
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in error_patterns]

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