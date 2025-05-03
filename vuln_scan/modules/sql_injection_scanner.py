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

    def safe_decode(self, value):
        """安全地解码任何值，处理所有可能的编码错误"""
        if value is None:
            return ""

        if isinstance(value, bytes):
            try:
                return value.decode('utf-8', errors='replace')
            except Exception:
                # 尝试其他编码格式
                for encoding in ['latin1', 'cp1252', 'iso-8859-1', 'gbk']:
                    try:
                        return value.decode(encoding, errors='replace')
                    except:
                        continue

                # 如果所有解码尝试都失败，返回十六进制表示
                try:
                    return f"[二进制数据: {value[:20].hex()}...]"
                except:
                    return "[二进制数据]"

        if isinstance(value, str):
            # 如果已经是字符串，确保它是有效的UTF-8
            try:
                return value.encode('utf-8', errors='replace').decode('utf-8')
            except Exception:
                return "[编码错误的字符串]"

        # 处理其他类型
        try:
            return str(value)
        except Exception:
            return "[无法转换为字符串的对象]"

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
            print(f"警告: 没有可用的SQL注入载荷规则，跳过SQL注入扫描")
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

        # 3. 检查HTTP头中的SQL注入 - 只有当明确配置了HTTP头规则时才执行
        if http_headers and len(http_headers) > 0:
            print(f"执行HTTP头扫描，配置的头部: {http_headers}")
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
        else:
            print("没有配置HTTP头规则，跳过HTTP头扫描")

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

        # 如果没有找到规则，返回默认的载荷
        print("未找到回显型SQL注入规则，使用默认载荷")
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
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('sql_injection', 'blind')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            return rule_content['payloads']

        # 如果没有找到规则，返回默认的载荷
        print("未找到盲注型SQL注入规则，使用默认载荷")
        return [
            "' OR (SELECT SLEEP(5))--",
            "'; SELECT SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND (SELECT COUNT(*) FROM ALL_USERS t1,ALL_USERS t2)>0--",
            "' AND 1=dbms_pipe.receive_message('RDS',10)--"
        ]

    async def get_http_headers_to_test(self, context):
        """获取要测试的HTTP头列表"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('sql_injection', 'http_header')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            # 从规则中获取要测试的HTTP头列表
            headers = rule_content['payloads']
            print(f"从数据库获取到HTTP头规则: {headers}")
            return headers

        # 如果没有找到规则，返回默认值
        print("未找到HTTP头注入规则，使用默认HTTP头")
        return [
            "Cookie",
            "X-Forwarded-For",
            "Referer",
            "User-Agent",
            "Authorization"
        ]

    async def get_error_patterns(self, context):
        """获取SQL错误匹配模式"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('sql_injection', 'error_pattern')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            return rule_content['payloads']

        # 如果没有找到规则，返回默认的匹配模式
        print("未找到SQL错误匹配模式规则，使用默认匹配模式")
        return [
            r"SQL syntax.*MySQL",
            r"Warning.*mysqli",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that (corresponds to|fits) your MySQL server version",
            r"MySqlClient\\.",
            r"com\\.mysql\\.jdbc\\.exceptions",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"SQLSTATE\\[",
            r"SQL Server message",
            r"Warning.*mssql_",
            r"Driver.*? SQL[\\-\\_\\ ]*Server",
            r"JET Database Engine",
            r"Microsoft Access Driver",
            r"Syntax error \\(missing operator\\) in query expression"
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
                                error_match, matched_pattern = self.check_sql_error_with_match(response_text,
                                                                                               error_patterns)
                                if error_match:
                                    # 记录漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 创建漏洞结果，包含匹配到的具体错误信息
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
                                        'response': f"HTTP/1.1 {response.status} {response.reason}\n{response_text[:1000]}",
                                        'proof': f"在参数 {param} 中注入 {payload} 后，响应中包含SQL错误信息: {matched_pattern}"
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
                                # 获取响应文本，但限制长度以防止占用过多内存
                                response_text = await response.text(errors='replace')
                                response_text = response_text[:1000]  # 只保留前1000个字符

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
                                        'response': f"HTTP/1.1 {response.status} {response.reason}\n响应时间: {response_time}秒\n{response_text}",
                                        'proof': f"在参数 {param} 中注入 {payload} 后，响应时间达到 {response_time:.2f} 秒，超过了预期的 {self.time_delay} 秒"
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

    # [同样改进scan_post_parameters和scan_http_headers方法，省略具体实现]

    def check_sql_error_with_match(self, response_text, error_patterns=None):
        """
        检查响应中是否包含SQL错误信息，并返回匹配的模式

        参数:
            response_text: 响应文本
            error_patterns: 错误模式列表

        返回:
            (布尔值, 匹配的模式) 元组
        """
        if not response_text:
            return False, None

        # 如果没有提供错误模式，返回一些默认的错误模式
        if not error_patterns:
            error_patterns = [
                r"SQL syntax.*MySQL",
                r"Warning.*mysqli",
                r"ORA-[0-9][0-9][0-9][0-9]",
                r"SQLSTATE\[",
                r"SQL Server"
            ]

        # 编译正则表达式以提高性能
        compiled_patterns = []
        for pattern in error_patterns:
            try:
                compiled_patterns.append((re.compile(pattern, re.IGNORECASE), pattern))
            except Exception as e:
                print(f"编译正则表达式 '{pattern}' 时出错: {str(e)}")
                continue

        # 如果没有编译成功的模式，无法检查
        if not compiled_patterns:
            return False, None

        # 检查响应是否包含任何SQL错误信息
        for compiled_pattern, original_pattern in compiled_patterns:
            match = compiled_pattern.search(response_text)
            if match:
                # 尝试提取匹配的具体文本
                matched_text = match.group(0) if match.group(0) else original_pattern
                return True, matched_text

        return False, None

    def check_sql_error(self, response_text, error_patterns=None):
        """
        检查响应中是否包含SQL错误信息 (兼容旧版本)

        参数:
            response_text: 响应文本
            error_patterns: 错误模式列表
        """
        result, _ = self.check_sql_error_with_match(response_text, error_patterns)
        return result

    def clear_cache(self):
        """清除缓存"""
        self.scanned_urls.clear()
        self.found_vulnerabilities.clear()
        print("SQL注入扫描器缓存已清除")