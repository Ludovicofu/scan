# vuln_scan/modules/ssrf_scanner.py
import json
import aiohttp
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode
from asgiref.sync import sync_to_async
from rules.models import VulnScanRule


class SsrfScanner:
    """
    SSRF扫描器：检测服务器端请求伪造漏洞
    """

    def __init__(self):
        """初始化扫描器"""
        self.ssrf_payloads = []  # SSRF测试载荷
        self.rules_loaded = False  # 规则是否已加载
        self.rules_last_check = 0  # 上次检查规则的时间
        self.rules_check_interval = 300  # 规则检查间隔（秒）

        # 记录已扫描的URL，避免重复扫描
        self.scanned_urls = set()

        # 记录已发现的漏洞，避免重复报告
        self.found_vulnerabilities = set()

    def clear_cache(self):
        """清除缓存"""
        self.rules_loaded = False
        self.scanned_urls.clear()
        self.found_vulnerabilities.clear()

    async def load_payloads(self):
        """从数据库加载SSRF测试载荷"""
        try:
            current_time = asyncio.get_event_loop().time()

            # 如果规则已加载且未超过检查间隔，则跳过
            if self.rules_loaded and (current_time - self.rules_last_check < self.rules_check_interval):
                return True

            # 加载SSRF载荷
            payload_rules = await self._get_rules_by_type_and_subtype('ssrf', 'payload')

            if payload_rules:
                try:
                    rule_content = json.loads(payload_rules[0].rule_content)
                    self.ssrf_payloads = rule_content.get('payloads', [])
                    print(f"已加载 {len(self.ssrf_payloads)} 条SSRF测试载荷")
                    if not self.ssrf_payloads:
                        print("警告：没有从数据库加载到任何SSRF载荷")
                        return False
                except Exception as e:
                    print(f"解析SSRF载荷规则内容失败: {str(e)}")
                    return False
            else:
                print("未找到SSRF载荷规则，无法继续扫描")
                return False

            # 更新规则加载状态
            self.rules_loaded = True
            self.rules_last_check = current_time

            return True
        except Exception as e:
            print(f"加载SSRF规则失败: {str(e)}")
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
                    # 如果JSON解析失败，尝试字符串匹配
                    if f'"subType": "{subtype}"' in rule.rule_content or f'"subType":"{subtype}"' in rule.rule_content:
                        rules.append(rule)
                except Exception as e:
                    print(f"解析规则内容出错: {str(e)}")
                    continue

            return rules
        except Exception as e:
            print(f"获取规则失败: {str(e)}")
            return []

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
        """执行SSRF扫描"""
        # 加载规则，如果没有规则则跳过扫描
        rules_loaded = await self.load_payloads()
        if not rules_loaded:
            return []

        # 获取上下文数据
        asset = context['asset']
        url = context['url']
        method = context['method']
        req_headers = context['req_headers']
        req_content = context['req_content']

        # 如果URL已扫描，则跳过
        if url in self.scanned_urls:
            return []

        # 标记为已扫描
        self.scanned_urls.add(url)

        # 检查是否是GET或POST请求
        if method not in ['GET', 'POST']:
            return []

        # 准备结果
        results = []

        # 1. 检查URL参数中的SSRF
        if '?' in url:
            url_results = await self.scan_url_parameters(context, url, self.ssrf_payloads)
            results.extend(url_results)

        # 2. 检查POST请求中的SSRF
        if method == 'POST' and req_content:
            post_results = await self.scan_post_parameters(context, url, req_content, self.ssrf_payloads)
            results.extend(post_results)

        return results

    async def scan_url_parameters(self, context, url, ssrf_payloads):
        """扫描URL参数中的SSRF漏洞"""
        results = []

        try:
            # 解析URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # 如果没有参数，直接返回
            if not query_params:
                return results

            # 创建HTTP客户端
            timeout = aiohttp.ClientTimeout(total=context.get('scan_timeout', 10))
            connector = None
            if context.get('use_proxy', False):
                connector = aiohttp.ProxyConnector.from_url(context.get('proxy_address', 'http://localhost:7890'))

            # 测试每个参数，不做任何预设参数过滤
            for param, values in query_params.items():
                if not values:
                    continue

                original_value = values[0]

                # 测试每个SSRF载荷
                for payload in ssrf_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"ssrf_url_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建测试URL - 直接替换参数值
                    test_params = query_params.copy()
                    test_params[param] = [payload]  # 直接替换为payload
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    if test_query:
                        test_url += f"?{test_query}"

                    # 发送请求
                    try:
                        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                            async with session.get(test_url) as response:
                                status = response.status

                                # 只要返回状态码在200-399之间，就认为测试成功
                                if 200 <= status < 400:
                                    # 构造请求数据
                                    request_data = f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}"

                                    # 标记为已发现的漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 添加结果
                                    results.append({
                                        'vuln_type': 'ssrf',
                                        'vuln_subtype': self._determine_ssrf_subtype(payload),
                                        'name': f'URL参数 {param} 中的SSRF漏洞',
                                        'description': f'在URL参数 {param} 中发现SSRF漏洞，可以访问服务器内网或本地资源',
                                        'severity': 'high',
                                        'url': url,
                                        'request': request_data,
                                        'response': f"HTTP/1.1 {status} OK",
                                        'proof': f"在URL参数 {param} 中注入 {payload} 成功，状态码: {status}",
                                        'parameter': param,
                                        'payload': payload
                                    })

                                    # 每个参数只添加一个结果
                                    break
                    except Exception:
                        continue
        except Exception:
            pass

        return results

    async def scan_post_parameters(self, context, url, req_content, ssrf_payloads):
        """扫描POST请求参数中的SSRF漏洞"""
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
                except Exception:
                    pass
            elif content_type and 'application/json' in content_type:
                # 处理JSON数据
                try:
                    json_data = json.loads(self.safe_decode(req_content))

                    # 将JSON扁平化为键值对
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
                except Exception:
                    pass
            else:
                # 尝试直接解析为表单数据
                try:
                    post_params = parse_qs(self.safe_decode(req_content))
                except Exception:
                    pass

            # 如果没有参数，直接返回
            if not post_params:
                return results

            # 创建HTTP客户端
            timeout = aiohttp.ClientTimeout(total=context.get('scan_timeout', 10))
            connector = None
            if context.get('use_proxy', False):
                connector = aiohttp.ProxyConnector.from_url(context.get('proxy_address', 'http://localhost:7890'))

            # 测试每个参数，不做任何预设参数过滤
            for param, values in post_params.items():
                if not values:
                    continue

                original_value = values[0]

                # 测试每个SSRF载荷
                for payload in ssrf_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"ssrf_post_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        continue

                    # 创建测试参数 - 直接替换参数值
                    test_params = post_params.copy()
                    test_params[param] = [payload]  # 直接替换为payload

                    # 根据content_type准备请求内容
                    if content_type and 'application/json' in content_type:
                        # 将扁平的参数还原为JSON
                        test_json = {}
                        for k, v in test_params.items():
                            # 简单处理，仅支持顶级键
                            test_json[k] = v[0]
                        test_content = json.dumps(test_json)
                        headers = {'Content-Type': 'application/json'}
                    else:
                        # 默认使用表单格式
                        test_content = urlencode(test_params, doseq=True)
                        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

                    # 发送请求
                    try:
                        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                            async with session.post(url, data=test_content, headers=headers) as response:
                                status = response.status

                                # 只要返回状态码在200-399之间，就认为测试成功
                                if 200 <= status < 400:
                                    # 构造请求数据
                                    request_data = f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {headers['Content-Type']}\n\n{test_content}"

                                    # 标记为已发现的漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 添加结果
                                    results.append({
                                        'vuln_type': 'ssrf',
                                        'vuln_subtype': self._determine_ssrf_subtype(payload),
                                        'name': f'POST参数 {param} 中的SSRF漏洞',
                                        'description': f'在POST参数 {param} 中发现SSRF漏洞，可以访问服务器内网或本地资源',
                                        'severity': 'high',
                                        'url': url,
                                        'request': request_data,
                                        'response': f"HTTP/1.1 {status} OK",
                                        'proof': f"在POST参数 {param} 中注入 {payload} 成功，状态码: {status}",
                                        'parameter': param,
                                        'payload': payload
                                    })

                                    # 每个参数只添加一个结果
                                    break
                    except Exception:
                        continue
        except Exception:
            pass

        return results

    def _determine_ssrf_subtype(self, payload):
        """确定SSRF漏洞的子类型"""
        # 根据payload确定SSRF子类型
        if 'file:' in payload:
            return 'file_protocol'
        elif any(term in payload.lower() for term in ['127.0.0.1', 'localhost', '192.168.', '10.']):
            return 'internal_network'
        else:
            return 'general_ssrf'  # 通用SSRF