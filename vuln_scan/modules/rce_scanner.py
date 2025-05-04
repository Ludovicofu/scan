# vuln_scan/modules/rce_scanner.py
import re
import json
import asyncio
import aiohttp
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from asgiref.sync import sync_to_async
from django.utils import timezone
from rules.models import VulnScanRule


class RceScanner:
    """
    远程代码/命令执行扫描模块：负责检测RCE漏洞
    """

    def __init__(self):
        """初始化扫描器"""
        # 记录已扫描的URL，避免重复扫描
        self.scanned_urls = set()

        # 记录已发现的漏洞，避免重复报告
        self.found_vulnerabilities = set()

        # 载荷和匹配模式
        self.payloads = []  # RCE测试载荷
        self.match_patterns = []  # RCE匹配模式

        # 规则是否已加载
        self.rules_loaded = False

        # 默认超时时间
        self.timeout = 10

    def clear_cache(self):
        """清除缓存"""
        self.scanned_urls.clear()
        self.found_vulnerabilities.clear()
        self.rules_loaded = False
        print("RCE扫描器缓存已清除")

    async def scan(self, context):
        """
        执行RCE漏洞扫描

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

        # 如果URL已扫描，则跳过
        if url in self.scanned_urls:
            return []

        # 标记为已扫描
        self.scanned_urls.add(url)

        # 如果规则尚未加载，加载规则
        if not self.rules_loaded:
            # 加载RCE载荷
            payload_loaded = await self.load_payloads()
            # 加载匹配模式
            pattern_loaded = await self.load_match_patterns()

            # 只有当载荷加载成功时才继续扫描
            if not payload_loaded:
                print(f"未成功加载RCE载荷，跳过RCE扫描")
                return []

            self.rules_loaded = True

        # 如果没有载荷，跳过扫描
        if not self.payloads:
            print(f"没有可用的RCE载荷，跳过RCE扫描")
            return []

        results = []

        # 1. 检查URL参数中的RCE
        if '?' in url:
            url_results = await self.scan_url_parameters(
                context,
                url,
                self.payloads,
                self.match_patterns
            )
            results.extend(url_results)

        # 2. 检查POST请求中的RCE
        if method == 'POST' and req_content:
            post_results = await self.scan_post_parameters(
                context,
                url,
                req_content,
                self.payloads,
                self.match_patterns
            )
            results.extend(post_results)

        return results

    async def load_payloads(self):
        """加载RCE测试载荷"""
        try:
            # 从数据库获取RCE载荷规则
            rule_content = await self._get_rule_from_db('command_injection', 'payload')

            if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
                self.payloads = rule_content['payloads']
                print(f"已加载 {len(self.payloads)} 条RCE载荷")
                return True
            else:
                print("未找到RCE载荷规则，跳过RCE扫描")
                self.payloads = []
                return False

        except Exception as e:
            print(f"加载RCE载荷规则失败: {str(e)}")
            return False

    async def load_match_patterns(self):
        """加载RCE匹配模式"""
        try:
            # 从数据库获取RCE匹配模式规则
            rule_content = await self._get_rule_from_db('command_injection', 'match_pattern')

            if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
                self.match_patterns = rule_content['payloads']
                print(f"已加载 {len(self.match_patterns)} 条RCE匹配模式")
                return True
            else:
                print("未找到RCE匹配模式规则，使用空匹配模式")
                self.match_patterns = []
                return True  # 返回True是因为匹配模式不是必需的

        except Exception as e:
            print(f"加载RCE匹配模式规则失败: {str(e)}")
            self.match_patterns = []
            return True  # 返回True是因为匹配模式不是必需的

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
                            # 尝试重新解析，如果失败则返回None
                            return json.loads(rule.rule_content)
                        except:
                            pass

            # 如果没有找到匹配的规则，返回None
            return None
        except Exception as e:
            print(f"从数据库获取规则时出错: {str(e)}")
            return None

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

    async def scan_url_parameters(self, context, url, payloads, match_patterns):
        """扫描URL参数中的RCE漏洞"""
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

                # 测试RCE载荷
                for payload in payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"rce_url_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建测试URL
                    test_params = query_params.copy()
                    test_params[param] = [original_value + payload]  # 附加到原始值后面
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

                                # 构建完整的HTTP响应内容
                                headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                                full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text[:1000]}"  # 限制响应大小

                                # 检查是否存在RCE
                                is_vulnerable, matched_pattern = self.check_rce_vulnerability(
                                    response_text,
                                    payload,
                                    match_patterns
                                )

                                if is_vulnerable:
                                    # 记录漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 创建漏洞结果
                                    result = {
                                        'vuln_type': 'command_injection',
                                        'name': f'URL参数 {param} 中的命令执行漏洞',
                                        'description': f'在URL参数 {param} 中发现命令执行漏洞',
                                        'severity': 'high',
                                        'url': test_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'request': f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}",
                                        'response': full_response,
                                        'proof': f"在参数 {param} 中注入 {payload} 后，执行结果: {matched_pattern}"
                                    }

                                    results.append(result)
                                    break  # 找到一个参数的漏洞后，不再测试该参数的其他载荷
                        except Exception as e:
                            print(f"测试URL参数 {param} 时出错: {str(e)}")
                            continue

        except Exception as e:
            print(f"扫描URL参数RCE时出错: {str(e)}")

        return results

    async def scan_post_parameters(self, context, url, req_content, payloads, match_patterns):
        """扫描POST请求参数中的RCE漏洞"""
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
                test_tasks = []

                # 测试RCE载荷
                for payload in payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"rce_post_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建测试参数
                    test_params = post_params.copy()
                    test_params[param] = [original_value + payload]  # 附加到原始值后面

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

                                # 构造完整的HTTP响应内容
                                headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                                full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text[:1000]}"  # 限制响应大小

                                # 检查是否存在RCE
                                is_vulnerable, matched_pattern = self.check_rce_vulnerability(
                                    response_text,
                                    payload,
                                    match_patterns
                                )

                                if is_vulnerable:
                                    # 记录漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 创建漏洞结果
                                    result = {
                                        'vuln_type': 'command_injection',
                                        'name': f'POST参数 {param} 中的命令执行漏洞',
                                        'description': f'在POST参数 {param} 中发现命令执行漏洞',
                                        'severity': 'high',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'request': f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {content_type}\n\n{test_content[:1000]}",
                                        'response': full_response,
                                        'proof': f"在参数 {param} 中注入 {payload} 后，执行结果: {matched_pattern}"
                                    }

                                    results.append(result)
                                    break  # 找到一个参数的漏洞后，不再测试该参数的其他载荷
                        except Exception as e:
                            print(f"测试POST参数 {param} 的RCE漏洞时出错: {str(e)}")
                            continue

        except Exception as e:
            print(f"扫描POST参数RCE时出错: {str(e)}")

        return results

    def check_rce_vulnerability(self, response_text, payload, match_patterns=None):
        """
        检查响应是否包含RCE的结果

        参数:
            response_text: 响应文本
            payload: 使用的测试载荷，用于判断某些特定标记
            match_patterns: 匹配模式列表

        返回:
            (is_vulnerable, matched_pattern) 元组
        """
        if not response_text:
            return False, None

        # 如果有匹配模式，使用匹配模式检测
        if match_patterns and len(match_patterns) > 0:
            for pattern in match_patterns:
                try:
                    # 尝试编译正则表达式
                    try:
                        regex = re.compile(pattern, re.IGNORECASE)
                        match = regex.search(response_text)
                        if match:
                            return True, match.group(0)
                    except re.error:
                        # 如果正则表达式无效，尝试直接字符串匹配
                        if pattern in response_text:
                            return True, pattern
                except Exception as e:
                    print(f"匹配模式检测出错: {str(e)}")
                    continue

        # 如果没有显式的匹配，检查载荷中是否包含特定标记
        # 例如，如果载荷中包含特定的标记字符串，则检查响应中是否包含这些标记
        if "|echo" in payload:
            # 从|echo cmd_inj_test类型的载荷中提取测试标记
            match = re.search(r"\|echo\s+(\w+)", payload)
            if match and match.group(1) in response_text:
                return True, match.group(1)

        if "print" in payload:
            # 从类似print('test')的载荷中提取测试标记
            match = re.search(r"print\(['\"](.*?)['\"]\)", payload)
            if match and match.group(1) in response_text:
                return True, match.group(1)

        # 检查常见的命令输出模式，但不硬编码完整规则
        # 这里只检查与载荷相关的可能输出

        return False, None