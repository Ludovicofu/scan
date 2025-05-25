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

    def safe_decode(self, value):
        """安全地解码任何值，处理所有可能的编码错误"""
        if value is None:
            return ""

        if isinstance(value, bytes):
            # 尝试多种编码格式
            encodings = ['utf-8', 'latin1', 'cp1252', 'iso-8859-1', 'gbk', 'gb2312', 'big5']
            for encoding in encodings:
                try:
                    return value.decode(encoding)
                except Exception:
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
        http_headers = await self.get_http_headers_to_test(context)
        error_patterns = await self.get_error_patterns(context)

        # 检查是否有规则可用
        if not error_based_payloads:
            print(f"警告: 没有可用的SQL注入载荷规则，跳过SQL注入扫描")
            return []

        results = []

        # 1. 检查URL参数中的SQL注入
        if '?' in url:
            url_results = await self.scan_url_parameters(
                context,
                url,
                error_based_payloads,
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

        # 如果没有找到规则，返回空列表
        print("未找到回显型SQL注入规则，跳过该类型的扫描")
        return []

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

        # 如果没有找到规则，返回空列表
        print("未找到HTTP头注入规则，跳过HTTP头扫描")
        return []

    async def get_error_patterns(self, context):
        """获取SQL错误匹配模式"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('sql_injection', 'error_pattern')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            return rule_content['payloads']

        # 如果没有找到规则，返回空列表
        print("未找到SQL错误匹配模式规则，可能会影响检测准确性")
        return []

    async def scan_url_parameters(self, context, url, error_payloads, error_patterns):
        """扫描URL参数中的SQL注入漏洞"""
        results = []

        # 如果没有载荷，直接返回
        if not error_payloads:
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
                                # 获取完整的响应文本
                                response_text = await response.text(errors='replace')

                                # 获取所有响应头
                                headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])

                                # 构建完整的HTTP响应内容
                                full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text}"

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
                                        'response': full_response,
                                        'proof': f"在参数 {param} 中注入 {payload} 后，响应中包含SQL错误信息: {matched_pattern}"
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

    async def scan_post_parameters(self, context, url, req_content, error_payloads, error_patterns):
        """扫描POST请求参数中的SQL注入漏洞 - 合并版（不再调用额外的方法）"""
        results = []

        # 如果没有载荷，直接返回
        if not error_payloads:
            return results

        try:
            # 解析URL获取主机信息
            parsed_url = urlparse(url)

            # 尝试解析请求内容
            if not req_content:
                return results

            # 检查请求内容类型并解析
            content_type = None
            for key, value in context.get('req_headers', {}).items():
                if key.lower() == 'content-type':
                    content_type = value.lower()
                    break

            post_params = {}

            # 改进的内容解码
            if isinstance(req_content, bytes):
                decoded_req_content = self.safe_decode(req_content)
            else:
                decoded_req_content = str(req_content)

            # 打印原始请求内容，帮助调试
            print(f"原始POST请求内容: {decoded_req_content[:200]}...")
            print(f"Content-Type: {content_type}")

            # 处理不同的内容类型
            if content_type and 'application/x-www-form-urlencoded' in content_type:
                # 处理表单数据
                try:
                    # 先尝试直接解析
                    post_params = parse_qs(decoded_req_content, keep_blank_values=True)

                    # 如果没有解析出参数，尝试手动解析
                    if not post_params and '=' in decoded_req_content:
                        # 手动解析表单数据
                        pairs = decoded_req_content.split('&')
                        for pair in pairs:
                            if '=' in pair:
                                key, value = pair.split('=', 1)
                                # URL解码
                                key = urllib.parse.unquote_plus(key)
                                value = urllib.parse.unquote_plus(value)
                                if key not in post_params:
                                    post_params[key] = []
                                post_params[key].append(value)

                    print(f"解析的表单参数: {post_params}")
                except Exception as e:
                    print(f"解析表单数据时出错: {str(e)}")

            elif content_type and 'application/json' in content_type:
                # 处理JSON数据
                try:
                    json_data = json.loads(decoded_req_content)
                    print(f"解析的JSON数据: {json_data}")

                    # 改进的JSON扁平化函数
                    def flatten_json(json_obj, prefix=''):
                        result = {}

                        if isinstance(json_obj, dict):
                            for key, value in json_obj.items():
                                new_key = f"{prefix}{key}" if prefix else key

                                if isinstance(value, dict):
                                    result.update(flatten_json(value, f"{new_key}."))
                                elif isinstance(value, list):
                                    for i, item in enumerate(value):
                                        if isinstance(item, (dict, list)):
                                            result.update(flatten_json(item, f"{new_key}[{i}]."))
                                        else:
                                            result[f"{new_key}[{i}]"] = str(item)
                                else:
                                    # 处理None值
                                    result[new_key] = str(value) if value is not None else ""
                        elif isinstance(json_obj, list):
                            for i, item in enumerate(json_obj):
                                if isinstance(item, (dict, list)):
                                    result.update(flatten_json(item, f"{prefix}[{i}]."))
                                else:
                                    result[f"{prefix}[{i}]"] = str(item)
                        else:
                            result[prefix.rstrip('.')] = str(json_obj)

                        return result

                    flattened = flatten_json(json_data)
                    # 转换为与parse_qs相同的格式 {param: [value]}
                    post_params = {k: [v] for k, v in flattened.items()}
                    print(f"扁平化后的JSON参数: {post_params}")

                except Exception as e:
                    print(f"解析JSON数据时出错: {str(e)}")
                    import traceback
                    traceback.print_exc()
            else:
                # 尝试多种解析方式
                try:
                    # 1. 先尝试作为表单数据解析
                    if '=' in decoded_req_content and '&' in decoded_req_content:
                        post_params = parse_qs(decoded_req_content, keep_blank_values=True)

                    # 2. 如果失败，尝试JSON解析
                    if not post_params and (
                            decoded_req_content.strip().startswith('{') or decoded_req_content.strip().startswith('[')):
                        try:
                            json_data = json.loads(decoded_req_content)
                            # 简单地转换JSON对象的顶级键值对
                            if isinstance(json_data, dict):
                                post_params = {k: [str(v)] for k, v in json_data.items()}
                            print(f"尝试解析为JSON数据: {post_params}")
                        except json.JSONDecodeError:
                            pass

                    # 3. 如果还是没有参数，尝试简单的键值对解析
                    if not post_params and '=' in decoded_req_content:
                        # 可能是单个参数或者特殊格式
                        if '&' not in decoded_req_content:
                            # 单个参数
                            key, value = decoded_req_content.split('=', 1)
                            post_params[urllib.parse.unquote_plus(key)] = [urllib.parse.unquote_plus(value)]
                        else:
                            # 手动解析
                            pairs = decoded_req_content.split('&')
                            for pair in pairs:
                                if '=' in pair:
                                    key, value = pair.split('=', 1)
                                    key = urllib.parse.unquote_plus(key)
                                    value = urllib.parse.unquote_plus(value)
                                    if key not in post_params:
                                        post_params[key] = []
                                    post_params[key].append(value)

                    if post_params:
                        print(f"使用备选方法解析的参数: {post_params}")

                except Exception as e:
                    print(f"解析未知类型的请求内容时出错: {str(e)}")

            # 如果没有参数，直接返回
            if not post_params:
                print("未能解析出任何POST参数，跳过SQL注入检测")
                return results

            print(f"最终解析出的参数数量: {len(post_params)}")

            # 测试每个参数
            for param, values in post_params.items():
                if not values:
                    values = [""]  # 确保空值也被测试

                original_value = values[0]
                print(f"测试参数: {param}={original_value}")

                # 测试每个载荷
                for payload in error_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"error_based_post_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 测试两种注入方式
                    test_methods = [
                        ('替换', payload),  # 直接替换原值
                        ('附加', original_value + payload)  # 附加到原值
                    ]

                    for method_name, test_value in test_methods:
                        # 创建测试参数
                        test_params = post_params.copy()
                        test_params[param] = [test_value]

                        # ============ 原本调用 _test_post_payload 的逻辑，现在直接写在这里 ============
                        try:
                            # 根据content_type准备请求内容
                            if content_type and 'application/json' in content_type:
                                # 还原为JSON格式
                                test_json = {}
                                for k, v in test_params.items():
                                    # 处理嵌套的键
                                    if '.' in k:
                                        # 处理形如 "user.name" 的键
                                        keys = k.split('.')
                                        current = test_json
                                        for key in keys[:-1]:
                                            if key not in current:
                                                current[key] = {}
                                            current = current[key]
                                        current[keys[-1]] = v[0]
                                    elif '[' in k and ']' in k:
                                        # 处理数组形式的键，如 "items[0]"
                                        # 这里简化处理，直接作为普通键
                                        test_json[k] = v[0]
                                    else:
                                        test_json[k] = v[0]

                                test_content = json.dumps(test_json, ensure_ascii=False)
                                headers = {'Content-Type': 'application/json'}
                            else:
                                # 默认使用表单格式
                                # 确保正确编码
                                encoded_params = {}
                                for k, v in test_params.items():
                                    encoded_params[k] = v[0] if v else ''

                                test_content = urlencode(encoded_params)
                                headers = {'Content-Type': 'application/x-www-form-urlencoded'}

                            print(f"测试 {method_name} payload: {param}={test_value[:50]}...")
                            print(f"请求内容预览: {test_content[:200]}...")

                            # 发送请求
                            async with aiohttp.ClientSession() as session:
                                try:
                                    async with session.post(
                                            url,
                                            data=test_content,
                                            headers=headers,
                                            timeout=self.timeout,
                                            ssl=False
                                    ) as response:
                                        # 获取完整的响应文本
                                        response_text = await response.text(errors='replace')
                                        status = response.status

                                        # 状态码检查
                                        print(f"响应状态码: {status}")

                                        # 打印响应长度，帮助调试
                                        print(f"响应长度: {len(response_text)} 字节")

                                        # 获取所有响应头
                                        headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])

                                        # 构建完整的HTTP响应内容
                                        full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text[:1000]}..."

                                        # 检查是否有SQL错误信息
                                        error_match, matched_pattern = self.check_sql_error_with_match(response_text,
                                                                                                       error_patterns)

                                        # 增强的错误检测：检查状态码500
                                        if not error_match and status >= 500:
                                            # 服务器错误可能也表示SQL注入
                                            print(f"检测到服务器错误状态码 {status}，可能存在SQL注入")
                                            error_match = True
                                            matched_pattern = f"HTTP {status} 服务器错误"

                                        if error_match:
                                            print(f"发现SQL错误匹配: {matched_pattern}")
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
                                                'request': f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {headers['Content-Type']}\n\n{test_content}",
                                                'response': full_response,
                                                'proof': f"在参数 {param} 中{method_name}注入 {payload} 后，响应中包含SQL错误信息: {matched_pattern}"
                                            }

                                            results.append(result)
                                            break  # 找到漏洞，跳出方法循环
                                        else:
                                            # 即使没有明显的错误，也检查响应是否异常
                                            if len(response_text) == 0 and status != 204:
                                                print(f"警告：响应为空，可能存在SQL注入导致的异常")

                                except aiohttp.ClientError as e:
                                    print(f"HTTP请求错误: {str(e)}")
                                    # 连接错误也可能是SQL注入导致的
                                    if "timeout" in str(e).lower():
                                        print("请求超时，可能是基于时间的盲注")
                                except Exception as e:
                                    print(f"测试POST参数 {param} 时出错: {str(e)}")

                        except Exception as e:
                            print(f"准备测试POST参数 {param} 时出错: {str(e)}")
                        # ============ 原本 _test_post_payload 的逻辑结束 ============

                        # 如果找到漏洞，跳出方法循环
                        if vuln_key in self.found_vulnerabilities:
                            break

                    # 如果已经找到漏洞，跳出载荷循环
                    if vuln_key in self.found_vulnerabilities:
                        break

        except Exception as e:
            print(f"扫描POST参数时出错: {str(e)}")
            import traceback
            traceback.print_exc()

        return results

    async def scan_http_headers(self, context, url, req_headers, http_headers_to_test, error_payloads, error_patterns):
        """
        扫描HTTP头中的SQL注入漏洞

        参数:
            context: 扫描上下文
            url: 目标URL
            req_headers: 请求头信息
            http_headers_to_test: 要测试的HTTP头列表
            error_payloads: 回显型注入载荷
            error_patterns: SQL错误模式

        返回:
            漏洞检测结果列表
        """
        results = []

        # 如果没有载荷或要测试的HTTP头，直接返回
        if not error_payloads or not http_headers_to_test:
            return results

        try:
            # 解析URL
            parsed_url = urlparse(url)

            # 只测试请求中实际包含的HTTP头
            headers_to_scan = []
            for header in http_headers_to_test:
                header_name = header.lower()
                # 检查请求头中是否包含该头部
                header_exists = False
                for req_header in req_headers:
                    if req_header.lower() == header_name:
                        header_exists = True
                        break

                if header_exists:
                    headers_to_scan.append(header)

            # 如果没有找到匹配的头部，直接返回
            if not headers_to_scan:
                print(f"在请求中未找到配置的HTTP头，跳过HTTP头扫描")
                return results

            print(f"将扫描以下HTTP头: {headers_to_scan}")

            # 测试每个HTTP头
            for header in headers_to_scan:
                # 获取原始值
                original_value = ""
                for key, value in req_headers.items():
                    if key.lower() == header.lower():
                        original_value = value
                        break

                # 如果没有找到原始值，使用默认值
                if not original_value:
                    original_value = "SQLi Test"

                # 测试回显型注入
                for payload in error_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"error_based_header_{header}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建测试头部
                    headers = {k: v for k, v in req_headers.items()}
                    headers[header] = original_value + payload

                    # 发送请求
                    async with aiohttp.ClientSession() as session:
                        try:
                            async with session.get(
                                    url,
                                    headers=headers,
                                    timeout=self.timeout,
                                    ssl=False
                            ) as response:
                                # 获取完整的响应文本
                                response_text = await response.text(errors='replace')

                                # 获取所有响应头
                                headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])

                                # 构建完整的HTTP响应内容
                                full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text}"

                                # 检查是否有SQL错误信息
                                error_match, matched_pattern = self.check_sql_error_with_match(response_text,
                                                                                               error_patterns)
                                if error_match:
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
                                        'request': f"GET {url} HTTP/1.1\nHost: {parsed_url.netloc}\n{header}: {original_value + payload}",
                                        'response': full_response,
                                        'proof': f"在HTTP头 {header} 中注入 {payload} 后，响应中包含SQL错误信息: {matched_pattern}"
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

        # 如果没有提供错误模式，使用默认模式
        if not error_patterns:
            error_patterns = [

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