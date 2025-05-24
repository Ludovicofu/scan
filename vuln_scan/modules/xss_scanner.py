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
    XSS扫描模块：负责检测跨站脚本漏洞 (统一检测方法)
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

        # 获取XSS载荷 - 统一获取所有XSS载荷
        xss_payloads = await self.get_xss_payloads(context)

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
                xss_payloads
            )
            results.extend(url_results)

        # 2. 检查POST请求中的XSS
        if method == 'POST' and req_content:
            post_results = await self.scan_post_parameters(
                context,
                url,
                req_content,
                xss_payloads
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

    async def get_xss_payloads(self, context):
        """获取XSS测试载荷（统一方法）"""
        # 从数据库获取规则
        rule_content = await self._get_rule_from_db('xss', 'payload')

        # 如果找到规则并且有payload字段，返回规则中的payload
        if rule_content and 'payloads' in rule_content and isinstance(rule_content['payloads'], list):
            payloads = rule_content['payloads']
            print(f"从数据库加载了 {len(payloads)} 个XSS测试载荷")
            return payloads

        # 如果没有找到规则，使用默认载荷
        default_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>"
        ]
        print(f"未找到XSS规则，使用 {len(default_payloads)} 个默认载荷")
        return default_payloads

    async def scan_url_parameters(self, context, url, xss_payloads):
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
                print(f"测试URL参数 {param}={original_value}")

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

                    print(f"测试URL: {test_url}")

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
                                status = response.status
                                print(f"响应状态码: {status}, 响应长度: {len(response_text)}")

                                # 检查XSS是否成功注入
                                if self.check_xss_injection(response_text, payload):
                                    print(f"URL参数 {param} 发现XSS漏洞!")
                                    # 获取所有响应头
                                    headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])

                                    # 构建完整的HTTP响应内容
                                    full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text[:1000]}..."

                                    # 记录漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 创建漏洞结果
                                    result = {
                                        'vuln_type': 'xss',
                                        'vuln_subtype': 'xss',  # 统一使用'xss'作为子类型
                                        'name': f'URL参数 {param} 中的XSS漏洞',
                                        'description': f'在URL参数 {param} 中发现跨站脚本(XSS)漏洞',
                                        'severity': 'high',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'request': f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}",
                                        'response': full_response,
                                        'proof': f"在参数 {param} 中注入 {payload} 后，响应包中包含相同的XSS载荷"
                                    }

                                    results.append(result)
                                    break  # 找到一个参数的漏洞后，就不再测试该参数的其他载荷
                        except Exception as e:
                            print(f"测试URL参数 {param} 时出错: {str(e)}")
                            continue

        except Exception as e:
            print(f"扫描URL参数XSS时出错: {str(e)}")
            import traceback
            traceback.print_exc()

        return results

    async def scan_post_parameters(self, context, url, req_content, xss_payloads):
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

            print(f"请求Content-Type: {content_type}")
            print(f"原始请求内容: {self.safe_decode(req_content)[:100]}...")

            post_params = {}

            # 处理不同的内容类型
            decoded_req_content = self.safe_decode(req_content)

            if content_type and 'application/x-www-form-urlencoded' in content_type:
                # 处理表单数据
                try:
                    post_params = parse_qs(decoded_req_content, keep_blank_values=True)
                    print(f"解析表单数据: {post_params}")
                except Exception as e:
                    print(f"解析表单数据时出错: {str(e)}")
            elif content_type and 'application/json' in content_type:
                # 处理JSON数据
                try:
                    json_data = json.loads(decoded_req_content)
                    print(f"解析JSON数据: {json_data}")

                    # 直接处理顶层键值对
                    for key, value in json_data.items():
                        if isinstance(value, (str, int, float, bool)):
                            post_params[key] = [str(value)]
                        elif value is None:
                            post_params[key] = [""]

                    print(f"提取JSON参数: {post_params}")
                except Exception as e:
                    print(f"解析JSON数据时出错: {str(e)}")
            else:
                # 尝试直接解析为表单数据
                try:
                    post_params = parse_qs(decoded_req_content, keep_blank_values=True)
                    print(f"尝试解析为表单数据: {post_params}")
                except Exception as e:
                    print(f"解析未知类型的请求内容时出错: {str(e)}")

            # 如果没有参数，直接返回
            if not post_params:
                print("未能解析出任何POST参数，跳过POST参数XSS扫描")
                return results

            # 测试每个参数
            for param, values in post_params.items():
                if not values:
                    values = [""]  # 确保空值也被测试

                original_value = values[0]
                print(f"测试POST参数 {param}={original_value}")

                # 测试每个XSS载荷
                for payload in xss_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"xss_post_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 直接测试载荷
                    result = await self._test_post_parameter(
                        url, parsed_url, param, payload, post_params,
                        content_type, vuln_key
                    )

                    if result:
                        results.append(result)
                        break  # 找到一个参数的漏洞后，就不再测试该参数的其他载荷

        except Exception as e:
            print(f"扫描POST参数XSS时出错: {str(e)}")
            import traceback
            traceback.print_exc()

        return results

    async def _test_post_parameter(self, url, parsed_url, param, payload, post_params, content_type, vuln_key):
        """测试单个POST参数的XSS漏洞"""
        try:
            # 创建测试参数
            test_params = post_params.copy()
            test_params[param] = [payload]  # 直接使用payload替换原值

            print(f"测试POST参数: {param}，载荷: {payload}")

            # 根据content_type准备请求内容
            if content_type and 'application/json' in content_type:
                # 简化JSON处理逻辑，避免复杂嵌套处理
                test_json = {}
                for k, v in test_params.items():
                    test_json[k] = v[0]
                test_content = json.dumps(test_json)
                headers = {'Content-Type': 'application/json'}
            else:
                # 默认使用表单格式
                test_content = urlencode(test_params, doseq=True)
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}

            print(f"发送POST请求: {url}")
            print(f"请求头: {headers}")
            print(f"请求内容: {test_content[:100]}...")

            # 发送POST请求
            async with aiohttp.ClientSession() as session:
                async with session.post(
                        url,
                        data=test_content,
                        headers=headers,
                        timeout=self.timeout,
                        ssl=False
                ) as response:
                    # 获取响应状态码
                    status = response.status
                    print(f"POST响应状态码: {status}")

                    # 获取完整的响应文本
                    response_text = await response.text(errors='replace')

                    # 检查响应长度，帮助调试
                    print(f"POST响应长度: {len(response_text)} 字节")

                    # 检查XSS是否成功注入 - 改进判断逻辑
                    xss_found = self.check_xss_injection(response_text, payload)
                    print(f"XSS检测结果: {'发现漏洞' if xss_found else '未发现漏洞'}")

                    if xss_found:
                        # 打印匹配到的内容片段
                        try:
                            match_index = response_text.lower().find(payload.lower())
                            if match_index >= 0:
                                context_start = max(0, match_index - 30)
                                context_end = min(len(response_text), match_index + len(payload) + 30)
                                match_context = response_text[context_start:context_end]
                                print(f"匹配上下文: ...{match_context}...")
                        except:
                            pass

                        # 获取所有响应头
                        headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])

                        # 构建完整的HTTP响应内容
                        full_response = f"HTTP/1.1 {response.status} {response.reason}\n{headers_text}\n\n{response_text[:1000]}..."

                        # 记录漏洞
                        self.found_vulnerabilities.add(vuln_key)

                        # 创建漏洞结果
                        result = {
                            'vuln_type': 'xss',
                            'vuln_subtype': 'xss',  # 统一使用'xss'作为子类型
                            'name': f'POST参数 {param} 中的XSS漏洞',
                            'description': f'在POST参数 {param} 中发现跨站脚本(XSS)漏洞',
                            'severity': 'high',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'request': f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {headers['Content-Type']}\n\n{test_content}",
                            'response': full_response,
                            'proof': f"在参数 {param} 中注入 {payload} 后，响应中包含XSS载荷"
                        }

                        return result
        except Exception as e:
            print(f"测试POST参数 {param} 的XSS漏洞时出错: {str(e)}")
            import traceback
            traceback.print_exc()

        return None

    def check_xss_injection(self, response_text, payload):
        """
        检查响应中是否包含XSS注入的载荷，表明XSS成功

        参数:
            response_text: 响应文本
            payload: XSS载荷
        """
        if not response_text or not payload:
            return False

        # 打印调试信息
        print(f"检查载荷: {payload}")

        # 先尝试直接查找载荷
        if payload in response_text:
            print(f"直接找到载荷: {payload}")
            return True

        # 对payload中的特殊字符进行转义，以便正则匹配
        try:
            escaped_payload = re.escape(payload)
            regex = re.compile(escaped_payload, re.IGNORECASE)
            if regex.search(response_text):
                print(f"正则匹配到载荷: {payload}")
                return True
        except Exception as e:
            print(f"正则匹配XSS载荷时出错: {str(e)}")

        # 尝试匹配可能的HTML编码变体
        try:
            # 简单替换几种常见的HTML实体编码
            encoded_variations = [
                payload.replace('<', '&lt;').replace('>', '&gt;'),
                payload.replace('<', '%3C').replace('>', '%3E'),
                payload.replace('"', '&quot;').replace("'", '&#39;')
            ]

            for encoded in encoded_variations:
                if encoded in response_text:
                    print(f"找到编码变体: {encoded}")
                    return True
        except Exception as e:
            print(f"检查编码变体时出错: {str(e)}")

        print(f"未找到载荷: {payload}")
        return False

    def clear_cache(self):
        """清除缓存"""
        self.scanned_urls.clear()
        self.found_vulnerabilities.clear()
        print("XSS扫描器缓存已清除")