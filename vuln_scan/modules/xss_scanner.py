# vuln_scan/modules/xss_scanner.py

import re
import json
import asyncio
import aiohttp
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from asgiref.sync import sync_to_async
from django.utils import timezone
from rules.models import VulnScanRule


class XssScanner:
    """
    XSS扫描模块：负责检测跨站脚本漏洞
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
        执行XSS扫描

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

        # 获取扫描配置 - 合并所有XSS载荷，不严格区分类型
        xss_payloads = await self.get_all_xss_payloads(context)
        context_patterns = await self.get_context_patterns(context)

        # 检查是否有规则可用
        if not xss_payloads:
            print(f"警告: 没有可用的XSS载荷规则，跳过XSS扫描")
            return []

        results = []

        # 1. 检查URL参数中的XSS
        if '?' in url:
            url_results = await self.scan_url_parameters(
                context,
                url,
                xss_payloads,
                context_patterns
            )
            results.extend(url_results)

        # 2. 检查POST请求中的XSS
        if method == 'POST' and req_content:
            post_results = await self.scan_post_parameters(
                context,
                url,
                req_content,
                xss_payloads,
                context_patterns
            )
            results.extend(post_results)

        # 3. 检查DOM XSS (需要浏览器引擎支持)
        dom_payloads = [p for p in xss_payloads if 'javascript:' in p or '#' in p]
        if dom_payloads:
            # 简化示例，实际DOM XSS检测需要浏览器引擎支持
            dom_results = await self.scan_dom_xss(
                context,
                url,
                dom_payloads
            )
            results.extend(dom_results)

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

    async def get_all_xss_payloads(self, context):
        """获取所有XSS测试载荷，不区分类型"""
        # 获取反射型XSS载荷
        reflected_payloads = await self.get_reflected_payloads(context)

        # 获取存储型XSS载荷
        stored_payloads = await self.get_stored_payloads(context)

        # 获取DOM型XSS载荷
        dom_payloads = await self.get_dom_payloads(context)

        # 合并所有载荷，去除重复
        all_payloads = list(set(reflected_payloads + stored_payloads + dom_payloads))

        return all_payloads

    async def get_reflected_payloads(self, context):
        """获取反射型XSS测试载荷"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('xss', 'reflected')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            return rule_content['payloads']

        # 如果没有找到规则，返回默认的载荷
        print("未找到反射型XSS规则，使用默认载荷")
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "';alert(1);//",
            "\"><script>alert(1)</script>",
            "<svg/onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\"></iframe>",
            "<body onload=alert(1)>",
            "javascript:alert(1)",
            "\"onmouseover=\"alert(1)",
            "'-alert(1)-'"
        ]

    async def get_stored_payloads(self, context):
        """获取存储型XSS测试载荷"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('xss', 'stored')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            return rule_content['payloads']

        # 如果没有找到规则，返回默认的载荷
        print("未找到存储型XSS规则，使用默认载荷")
        return [
            "<script>alert('stored_xss_1')</script>",
            "<img src=x onerror=alert('stored_xss_2')>",
            "<svg/onload=alert('stored_xss_3')>",
            "<iframe src=\"javascript:alert('stored_xss_4')\"></iframe>"
        ]

    async def get_dom_payloads(self, context):
        """获取DOM型XSS测试载荷"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('xss', 'dom')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            return rule_content['payloads']

        # 如果没有找到规则，返回默认的载荷
        print("未找到DOM型XSS规则，使用默认载荷")
        return [
            "javascript:alert(1)",
            "#<script>alert(1)</script>",
            "?q=<script>alert(1)</script>",
            "?param=';alert(1);//",
            "#javascript:alert(1)"
        ]

    async def get_context_patterns(self, context):
        """获取XSS上下文匹配模式"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('xss', 'context_pattern')

        # 如果找到规则并且有patterns字段，返回规则中的patterns
        if rule_content and 'patterns' in rule_content and isinstance(rule_content['patterns'], dict):
            return rule_content['patterns']

        # 如果没有找到规则，返回默认的匹配模式
        print("未找到XSS上下文匹配模式规则，使用默认匹配模式")
        return {
            "html": r"<[^>]*>(.*?)<\/[^>]*>",
            "attribute": r"<[^>]*[a-zA-Z0-9]+=(['\"])(.*?)\1[^>]*>",
            "javascript": r"<script[^>]*>(.*?)<\/script>",
            "url": r"(href|src|action|url)\s*=\s*(['\"])(.*?)\2"
        }

    async def scan_url_parameters(self, context, url, xss_payloads, context_patterns):
        """扫描URL参数中的XSS漏洞"""
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

                # 测试XSS载荷
                for payload in xss_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"xss_url_{param}_{url}"
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

                                # 检查XSS是否成功注入
                                if self.check_xss_injection(response_text, payload):
                                    # 确定XSS上下文
                                    xss_context = self.determine_xss_context(response_text, payload, context_patterns)

                                    # 构造完整的HTTP响应内容
                                    headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                                    full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text}"

                                    # 记录漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 确定XSS类型 (反射型还是DOM型)
                                    xss_subtype = 'dom' if '#' in payload or 'javascript:' in payload else 'reflected'

                                    # 创建漏洞结果
                                    result = {
                                        'vuln_type': 'xss',
                                        'vuln_subtype': xss_subtype,
                                        'name': f'URL参数 {param} 中的{self.get_xss_type_name(xss_subtype)}XSS漏洞',
                                        'description': f'在URL参数 {param} 中发现{self.get_xss_type_name(xss_subtype)}XSS漏洞，上下文: {xss_context}',
                                        'severity': 'high',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'request': f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}",
                                        'response': full_response,
                                        'proof': f"在参数 {param} 中注入 {payload} 后，上下文 {xss_context}，响应包中包含相同的XSS载荷"
                                    }

                                    results.append(result)
                                    break  # 找到一个参数的漏洞后，就不再测试该参数的其他载荷
                        except Exception as e:
                            print(f"测试URL参数 {param} 时出错: {str(e)}")
                            continue

        except Exception as e:
            print(f"扫描URL参数XSS时出错: {str(e)}")

        return results

    async def scan_post_parameters(self, context, url, req_content, xss_payloads, context_patterns):
        """扫描POST请求参数中的XSS漏洞"""
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

                # 测试XSS载荷
                for payload in xss_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"xss_post_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建任务
                    test_task = self._test_post_parameter(
                        url, parsed_url, param, payload, post_params,
                        content_type, vuln_key, context_patterns
                    )
                    test_tasks.append(test_task)

                # 并行执行测试任务
                if test_tasks:
                    # 使用信号量限制并发数
                    sem = asyncio.Semaphore(5)  # 最多5个并发测试

                    async def run_with_sem(task):
                        async with sem:
                            return await task

                    # 执行所有测试任务
                    test_results = await asyncio.gather(
                        *[run_with_sem(task) for task in test_tasks],
                        return_exceptions=True
                    )

                    # 处理结果
                    for result in test_results:
                        if result and not isinstance(result, Exception):
                            results.append(result)
                            # 找到一个漏洞后，不再测试该参数
                            break

        except Exception as e:
            print(f"扫描POST参数XSS时出错: {str(e)}")

        return results

    async def _test_post_parameter(self, url, parsed_url, param, payload, post_params, content_type, vuln_key,
                                   context_patterns):
        """测试单个POST参数的XSS漏洞"""
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

                    # 检查XSS是否成功注入
                    if self.check_xss_injection(response_text, payload):
                        # 确定XSS上下文
                        xss_context = self.determine_xss_context(response_text, payload, context_patterns)

                        # 构造完整的HTTP响应内容
                        headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                        full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text}"

                        # 记录漏洞
                        self.found_vulnerabilities.add(vuln_key)

                        # 尝试检测XSS类型
                        # 如果响应中包含完整的payload，可能是反射型或存储型
                        # 大多数情况下POST参数的XSS是存储型的，但也可能立即反射
                        xss_subtype = 'stored'  # 默认认为是存储型

                        # 创建漏洞结果
                        result = {
                            'vuln_type': 'xss',
                            'vuln_subtype': xss_subtype,
                            'name': f'POST参数 {param} 中的{self.get_xss_type_name(xss_subtype)}XSS漏洞',
                            'description': f'在POST参数 {param} 中发现{self.get_xss_type_name(xss_subtype)}XSS漏洞，上下文: {xss_context}',
                            'severity': 'high',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'request': f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {content_type}\n\n{test_content}",
                            'response': full_response,
                            'proof': f"在参数 {param} 中注入 {payload} 后，上下文 {xss_context}，响应包中包含相同的XSS载荷"
                        }

                        return result

            # 如果没有找到漏洞，可以再尝试GET请求以检测存储型XSS
            # 由于无法确定哪个URL会显示存储的内容，这里仅做示例
            # 在实际环境中，应根据具体应用逻辑确定可能的内容显示页面

            # 尝试请求自身URL，查看是否显示注入的内容
            async with aiohttp.ClientSession() as session:
                async with session.get(
                        url,
                        timeout=self.timeout,
                        ssl=False
                ) as response:
                    response_text = await response.text(errors='replace')

                    # 检查是否包含注入的payload
                    if self.check_xss_injection(response_text, payload):
                        # 确定XSS上下文
                        xss_context = self.determine_xss_context(response_text, payload, context_patterns)

                        # 构造完整的HTTP响应内容
                        headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                        full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text}"

                        # 记录漏洞
                        self.found_vulnerabilities.add(vuln_key)

                        # 创建漏洞结果
                        result = {
                            'vuln_type': 'xss',
                            'vuln_subtype': 'stored',
                            'name': f'POST参数 {param} 中的存储型XSS漏洞',
                            'description': f'在POST参数 {param} 中发现存储型XSS漏洞，上下文: {xss_context}',
                            'severity': 'high',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'request': f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {content_type}\n\n{test_content}",
                            'response': full_response,
                            'proof': f"在参数 {param} 中注入 {payload} 后，通过GET请求发现存储的XSS载荷，上下文: {xss_context}"
                        }

                        return result

        except Exception as e:
            print(f"测试POST参数 {param} 的XSS漏洞时出错: {str(e)}")
            return None

    async def scan_dom_xss(self, context, url, dom_payloads):
        """
        扫描DOM XSS漏洞
        注意：完整的DOM XSS扫描需要浏览器引擎支持，这里仅做简化演示
        """
        results = []

        try:
            # 这里简化处理，实际DOM XSS检测需要浏览器引擎或更复杂的处理
            parsed_url = urlparse(url)

            # 测试常见的DOM XSS位置: hash fragment
            for payload in dom_payloads:
                # 检测是否已存在相同漏洞
                vuln_key = f"dom_xss_{url}"
                if vuln_key in self.found_vulnerabilities:
                    continue

                # 创建带有测试载荷的URL
                test_url = f"{url}#{payload}"

                # 由于DOM XSS通常需要浏览器渲染执行JS，这里只做示意性测试
                # 实际检测应使用Selenium或Puppeteer等浏览器自动化工具

                # 模拟发现漏洞的情况（实际项目中需要完善这部分）
                if "document.location" in context.get('resp_content', '') or "window.location" in context.get(
                        'resp_content', ''):
                    # 可能存在DOM XSS的迹象，记录为可疑漏洞
                    self.found_vulnerabilities.add(vuln_key)

                    # 创建漏洞结果
                    result = {
                        'vuln_type': 'xss',
                        'vuln_subtype': 'dom',
                        'name': 'DOM型XSS漏洞',
                        'description': f'可能存在DOM型XSS漏洞，发现使用了不安全的location处理',
                        'severity': 'medium',  # DOM XSS通常需人工确认，先标记为中等
                        'url': url,
                        'parameter': 'fragment',
                        'payload': payload,
                        'request': f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}",
                        'response': context.get('resp_content', ''),
                        'proof': f"页面包含不安全的JavaScript代码，可能用于处理URL片段。建议手动验证使用 {test_url} 作为输入"
                    }

                    results.append(result)
                    break  # 找到漏洞后，不再测试其他载荷

        except Exception as e:
            print(f"扫描DOM XSS时出错: {str(e)}")

        return results

    def check_xss_injection(self, response_text, payload):
        """
        检查响应中是否包含XSS注入的载荷，表明XSS成功

        参数:
            response_text: 响应文本
            payload: XSS载荷
        """
        if not response_text or not payload:
            return False

        # 对payload中的特殊字符进行转义，以便正则匹配
        escaped_payload = re.escape(payload)

        # 尝试查找完全匹配的载荷
        try:
            if re.search(escaped_payload, response_text, re.IGNORECASE):
                return True
        except Exception as e:
            print(f"正则匹配XSS载荷时出错: {str(e)}")

        # 尝试匹配可能的HTML编码变体
        # 简单替换几种常见的HTML实体编码
        encoded_patterns = [
            escaped_payload.replace('\\<', '&lt;').replace('\\>', '&gt;'),
            escaped_payload.replace('\\<', '%3C').replace('\\>', '%3E'),
            escaped_payload.replace('\\"', '&quot;').replace("\\'", '&#39;')
        ]

        for pattern in encoded_patterns:
            try:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
            except Exception:
                continue

        return False

    def determine_xss_context(self, response_text, payload, context_patterns):
        """
        确定XSS注入点的上下文

        参数:
            response_text: 响应文本
            payload: XSS载荷
            context_patterns: 上下文匹配模式
        """
        if not response_text or not payload:
            return "未知上下文"

        escaped_payload = re.escape(payload)

        # 检查各种上下文
        try:
            # HTML标签上下文
            if re.search(f"<[^>]*{escaped_payload}[^>]*>", response_text):
                return "HTML标签上下文"

            # HTML属性上下文
            if re.search(f"<[^>]*=['\"][^'\"]*{escaped_payload}[^'\"]*['\"][^>]*>", response_text):
                return "HTML属性上下文"

            # JavaScript上下文
            if re.search(f"<script[^>]*>[^<]*{escaped_payload}[^<]*</script>", response_text) or \
                    re.search(f"javascript:[^'\"]*{escaped_payload}", response_text) or \
                    re.search(f"on[a-z]+=['\"][^'\"]*{escaped_payload}[^'\"]*['\"]", response_text):
                return "JavaScript上下文"

            # URL上下文
            if re.search(f"(href|src|action|url)\\s*=\\s*['\"][^'\"]*{escaped_payload}[^'\"]*['\"]", response_text):
                return "URL上下文"

            # CSS上下文
            if re.search(f"<style[^>]*>[^<]*{escaped_payload}[^<]*</style>", response_text) or \
                    re.search(f"style=['\"][^'\"]*{escaped_payload}[^'\"]*['\"]", response_text):
                return "CSS上下文"

        except Exception as e:
            print(f"确定XSS上下文时出错: {str(e)}")

        # 默认上下文
        return "HTML内容上下文"

    def get_xss_type_name(self, subtype):
        """获取XSS类型的中文名称"""
        type_names = {
            'reflected': '反射型',
            'stored': '存储型',
            'dom': 'DOM型'
        }
        return type_names.get(subtype, '')

    def clear_cache(self):
        """清除缓存"""
        self.scanned_urls.clear()
        self.found_vulnerabilities.clear()
        print("XSS扫描器缓存已清除")