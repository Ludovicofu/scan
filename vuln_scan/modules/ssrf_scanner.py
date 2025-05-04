# vuln_scan/modules/ssrf_scanner.py
import json
import re
import aiohttp
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from asgiref.sync import sync_to_async
from rules.models import VulnScanRule


class SsrfScanner:
    """
    SSRF扫描器：检测服务器端请求伪造漏洞
    """

    def __init__(self):
        """初始化扫描器"""
        print("SSRF扫描器初始化")
        self.ssrf_payloads = []  # SSRF测试载荷
        self.match_patterns = []  # 匹配模式
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
        print("SSRF扫描器缓存已清除")

    async def load_payloads(self):
        """
        从数据库加载SSRF测试载荷和匹配模式
        如果没有规则，返回False，跳过扫描
        """
        print("\n================== SSRF扫描器开始加载规则 ==================")
        try:
            current_time = asyncio.get_event_loop().time()

            # 如果规则已加载且未超过检查间隔，则跳过
            if self.rules_loaded and (current_time - self.rules_last_check < self.rules_check_interval):
                print("SSRF规则已加载且未过期，跳过重新加载")
                return True

            # 加载SSRF载荷
            payload_rules = await self._get_rules_by_type_and_subtype('ssrf', 'payload')
            print(f"查询到 {len(payload_rules)} 条SSRF载荷规则")

            if payload_rules:
                try:
                    rule_content = json.loads(payload_rules[0].rule_content)
                    self.ssrf_payloads = rule_content.get('payloads', [])
                    print(f"已加载 {len(self.ssrf_payloads)} 条SSRF测试载荷")
                    print(f"载荷样例: {self.ssrf_payloads[:3] if len(self.ssrf_payloads) > 3 else self.ssrf_payloads}")
                except Exception as e:
                    print(f"解析SSRF载荷规则内容失败: {str(e)}")
                    print(f"原始规则内容: {payload_rules[0].rule_content[:200]}...")
                    self.ssrf_payloads = []
            else:
                print("未找到SSRF载荷规则，不执行SSRF扫描")
                self.ssrf_payloads = []

            # 加载匹配模式
            pattern_rules = await self._get_rules_by_type_and_subtype('ssrf', 'match_pattern')
            print(f"查询到 {len(pattern_rules)} 条SSRF匹配模式规则")

            if pattern_rules:
                try:
                    rule_content = json.loads(pattern_rules[0].rule_content)
                    self.match_patterns = rule_content.get('payloads', [])
                    print(f"已加载 {len(self.match_patterns)} 条SSRF匹配模式")
                    print(
                        f"匹配模式样例: {self.match_patterns[:3] if len(self.match_patterns) > 3 else self.match_patterns}")
                except Exception as e:
                    print(f"解析SSRF匹配模式规则内容失败: {str(e)}")
                    print(f"原始规则内容: {pattern_rules[0].rule_content[:200]}...")
                    self.match_patterns = []
            else:
                print("未找到SSRF匹配模式规则，不执行SSRF扫描")
                self.match_patterns = []

            # 更新规则加载状态
            self.rules_loaded = True
            self.rules_last_check = current_time

            # 如果没有任何规则，返回False，跳过扫描
            if not self.ssrf_payloads or not self.match_patterns:
                print("SSRF规则不完整，跳过SSRF扫描")
                return False

            print("SSRF规则加载完成，准备开始扫描")
            print("================== SSRF规则加载完成 ==================\n")
            return True
        except Exception as e:
            print(f"加载SSRF规则失败: {str(e)}")
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

            print(f"查询到 {type_rules.count()} 条类型为 {vuln_type} 的规则")

            # 从规则内容中筛选子类型
            for rule in type_rules:
                try:
                    rule_content = json.loads(rule.rule_content)
                    if rule_content.get('subType') == subtype:
                        rules.append(rule)
                        print(f"找到符合子类型 {subtype} 的规则: ID={rule.id}, 名称={rule.name}")
                except json.JSONDecodeError:
                    print(f"规则ID {rule.id} JSON解析失败，尝试字符串匹配")
                    # 如果JSON解析失败，尝试字符串匹配
                    if f'"subType": "{subtype}"' in rule.rule_content or f'"subType":"{subtype}"' in rule.rule_content:
                        rules.append(rule)
                        print(f"通过字符串匹配找到符合子类型 {subtype} 的规则: ID={rule.id}")
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
        print(f"\n=========== SSRF扫描开始 ===========\n目标URL: {context['url']}")

        # 加载规则，如果没有规则则跳过扫描
        rules_loaded = await self.load_payloads()
        if not rules_loaded:
            print("SSRF规则加载失败，跳过扫描")
            return []

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
            print(f"URL {url} 已扫描，跳过")
            return []

        # 标记为已扫描
        self.scanned_urls.add(url)

        # 检查是否是GET或POST请求
        if method not in ['GET', 'POST']:
            print(f"请求方法 {method} 不是GET或POST，跳过")
            return []

        # 准备结果
        results = []

        # 检查URL中是否包含可能的SSRF参数（url, link, file, path等）
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        potential_ssrf_params = [
            param for param in query_params
            if param.lower() in ['url', 'link', 'site', 'uri', 'file', 'path', 'dest', 'redirect',
                                 'target', 'location', 'domain', 'callback', 'return', 'next', 'src']
        ]

        if potential_ssrf_params:
            print(f"发现潜在SSRF参数: {potential_ssrf_params}")

        # 1. 检查URL参数中的SSRF
        if '?' in url:
            print(f"开始扫描URL参数，共有 {len(parse_qs(urlparse(url).query))} 个参数")
            url_results = await self.scan_url_parameters(context, url, self.ssrf_payloads, self.match_patterns)
            results.extend(url_results)
            print(f"URL参数扫描完成，发现 {len(url_results)} 个SSRF漏洞")

        # 2. 检查POST请求中的SSRF
        if method == 'POST' and req_content:
            print(f"开始扫描POST参数")
            post_results = await self.scan_post_parameters(context, url, req_content, self.ssrf_payloads,
                                                           self.match_patterns)
            results.extend(post_results)
            print(f"POST参数扫描完成，发现 {len(post_results)} 个SSRF漏洞")

        print(f"\n=========== SSRF扫描结束 ===========\n共发现 {len(results)} 个SSRF漏洞")
        return results

    async def scan_url_parameters(self, context, url, ssrf_payloads, match_patterns):
        """扫描URL参数中的SSRF漏洞"""
        results = []

        try:
            # 解析URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # 如果没有参数，直接返回
            if not query_params:
                print("URL没有参数，跳过URL参数SSRF扫描")
                return results

            # 创建HTTP客户端
            timeout = aiohttp.ClientTimeout(total=context.get('scan_timeout', 10))
            connector = None
            if context.get('use_proxy', False):
                connector = aiohttp.ProxyConnector.from_url(context.get('proxy_address', 'http://localhost:7890'))

            # 测试每个参数
            for param, values in query_params.items():
                if not values:
                    continue

                original_value = values[0]
                print(f"测试URL参数: {param}，原始值: {original_value}")

                # 检查是否是URL类型参数
                is_url_param = param.lower() in ['url', 'link', 'site', 'uri', 'file', 'path', 'dest', 'redirect',
                                                 'target', 'location', 'domain', 'callback', 'return', 'next', 'src']

                if is_url_param:
                    print(f"参数 {param} 可能是URL类型参数，优先级提高")

                # 测试每个SSRF载荷
                for payload in ssrf_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"ssrf_url_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        print(f"参数 {param} 已检测到SSRF漏洞，跳过")
                        continue

                    # 创建测试URL - 直接替换参数值
                    test_params = query_params.copy()
                    test_params[param] = [payload]  # 直接替换为payload
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    if test_query:
                        test_url += f"?{test_query}"

                    print(f"测试SSRF载荷: {payload}，构造URL: {test_url}")

                    # 发送请求
                    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                        try:
                            async with session.get(test_url) as response:
                                status = response.status
                                response_text = await response.text()

                                print(f"请求状态码: {status}, 响应长度: {len(response_text)}")

                                # 检查是否存在SSRF特征
                                ssrf_match = self._check_ssrf_match(response_text, match_patterns)

                                if ssrf_match:
                                    print(f"发现SSRF特征: {ssrf_match}")

                                    # 确定SSRF子类型
                                    ssrf_subtype = self._determine_ssrf_subtype(payload, ssrf_match)

                                    # 构造请求数据
                                    request_data = f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}"

                                    # 构造响应数据
                                    response_data = f"HTTP/1.1 {status}\n\n{response_text[:300]}..."

                                    # 构造证明数据
                                    proof = f"在URL参数 {param} 中注入 {payload} 后，响应中包含匹配特征: {ssrf_match}"

                                    # 标记为已发现的漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 添加结果
                                    results.append({
                                        'vuln_type': 'ssrf',
                                        'vuln_subtype': ssrf_subtype,
                                        'name': f'URL参数 {param} 中的SSRF漏洞',
                                        'description': f'在URL参数 {param} 中发现SSRF漏洞，可以访问服务器内网或本地资源',
                                        'severity': 'high',
                                        'url': url,
                                        'request': request_data,
                                        'response': response_data,
                                        'proof': f"{proof}，访问结果: {ssrf_match}",
                                        'parameter': param,
                                        'payload': payload
                                    })

                                    # 每个参数只添加一个结果
                                    break
                                else:
                                    print(f"未发现SSRF特征")
                        except Exception as e:
                            print(f"测试URL参数 {param} 的SSRF漏洞时出错: {str(e)}")
                            continue
        except Exception as e:
            print(f"扫描URL参数SSRF时出错: {str(e)}")
            import traceback
            traceback.print_exc()

        return results

    async def scan_post_parameters(self, context, url, req_content, ssrf_payloads, match_patterns):
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

            print(f"POST请求Content-Type: {content_type}")

            post_params = {}

            # 处理不同的内容类型
            if content_type and 'application/x-www-form-urlencoded' in content_type:
                # 处理表单数据
                try:
                    post_params = parse_qs(self.safe_decode(req_content))
                    print(f"解析表单数据，共有 {len(post_params)} 个参数")
                except Exception as e:
                    print(f"解析表单数据时出错: {str(e)}")
            elif content_type and 'application/json' in content_type:
                # 处理JSON数据
                try:
                    json_data = json.loads(self.safe_decode(req_content))
                    print(f"解析JSON数据成功")

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
                    print(f"扁平化JSON数据，共有 {len(post_params)} 个参数")
                except Exception as e:
                    print(f"解析JSON数据时出错: {str(e)}")
            else:
                # 尝试直接解析为表单数据
                try:
                    post_params = parse_qs(self.safe_decode(req_content))
                    print(f"尝试解析为表单数据，共有 {len(post_params)} 个参数")
                except Exception as e:
                    print(f"解析未知类型的请求内容时出错: {str(e)}")

            # 如果没有参数，直接返回
            if not post_params:
                print("POST请求没有参数，跳过POST参数SSRF扫描")
                return results

            # 创建HTTP客户端
            timeout = aiohttp.ClientTimeout(total=context.get('scan_timeout', 10))
            connector = None
            if context.get('use_proxy', False):
                connector = aiohttp.ProxyConnector.from_url(context.get('proxy_address', 'http://localhost:7890'))

            # 测试每个参数
            for param, values in post_params.items():
                if not values:
                    continue

                original_value = values[0]
                print(f"测试POST参数: {param}，原始值: {original_value}")

                # 检查是否是URL类型参数
                is_url_param = param.lower() in ['url', 'link', 'site', 'uri', 'file', 'path', 'dest', 'redirect',
                                                 'target', 'location', 'domain', 'callback', 'return', 'next', 'src']

                if is_url_param:
                    print(f"参数 {param} 可能是URL类型参数，优先级提高")

                # 测试每个SSRF载荷
                for payload in ssrf_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"ssrf_post_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        print(f"参数 {param} 已检测到SSRF漏洞，跳过")
                        continue

                    # 创建测试参数 - 直接替换参数值
                    test_params = post_params.copy()
                    test_params[param] = [payload]  # 直接替换为payload

                    print(f"测试SSRF载荷: {payload}")

                    # 根据content_type准备请求内容
                    if content_type and 'application/json' in content_type:
                        # 将扁平的参数还原为JSON
                        test_json = {}
                        for k, v in test_params.items():
                            # 简单处理，仅支持顶级键
                            test_json[k] = v[0]
                        test_content = json.dumps(test_json)
                        headers = {'Content-Type': 'application/json'}
                        print(f"构造JSON请求体")
                    else:
                        # 默认使用表单格式
                        test_content = urlencode(test_params, doseq=True)
                        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                        print(f"构造表单请求体")

                    # 发送请求
                    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                        try:
                            async with session.post(url, data=test_content, headers=headers) as response:
                                status = response.status
                                response_text = await response.text()

                                print(f"请求状态码: {status}, 响应长度: {len(response_text)}")

                                # 检查是否存在SSRF特征
                                ssrf_match = self._check_ssrf_match(response_text, match_patterns)

                                if ssrf_match:
                                    print(f"发现SSRF特征: {ssrf_match}")

                                    # 确定SSRF子类型
                                    ssrf_subtype = self._determine_ssrf_subtype(payload, ssrf_match)

                                    # 构造请求数据
                                    request_data = f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {headers['Content-Type']}\n\n{test_content}"

                                    # 构造响应数据
                                    response_data = f"HTTP/1.1 {status}\n\n{response_text[:300]}..."

                                    # 构造证明数据
                                    proof = f"在POST参数 {param} 中注入 {payload} 后，响应中包含匹配特征: {ssrf_match}"

                                    # 标记为已发现的漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 添加结果
                                    results.append({
                                        'vuln_type': 'ssrf',
                                        'vuln_subtype': ssrf_subtype,
                                        'name': f'POST参数 {param} 中的SSRF漏洞',
                                        'description': f'在POST参数 {param} 中发现SSRF漏洞，可以访问服务器内网或本地资源',
                                        'severity': 'high',
                                        'url': url,
                                        'request': request_data,
                                        'response': response_data,
                                        'proof': f"{proof}，访问结果: {ssrf_match}",
                                        'parameter': param,
                                        'payload': payload
                                    })

                                    # 每个参数只添加一个结果
                                    break
                                else:
                                    print(f"未发现SSRF特征")
                        except Exception as e:
                            print(f"测试POST参数 {param} 的SSRF漏洞时出错: {str(e)}")
                            continue
        except Exception as e:
            print(f"扫描POST参数SSRF时出错: {str(e)}")
            import traceback
            traceback.print_exc()

        return results

    def _check_ssrf_match(self, response_text, match_patterns):
        """检查响应中是否包含SSRF访问结果的特征"""
        if not response_text or not match_patterns:
            print("没有响应文本或匹配模式，无法检查SSRF特征")
            return None

        # 对每个匹配模式进行检查
        for pattern in match_patterns:
            try:
                # 尝试正则表达式匹配
                regex = re.compile(pattern, re.IGNORECASE)
                match = regex.search(response_text)
                if match:
                    print(f"找到匹配模式 '{pattern}'，匹配内容: '{match.group(0)}'")
                    return match.group(0)
            except Exception as e:
                print(f"正则表达式 '{pattern}' 匹配出错: {str(e)}")

                # 如果正则表达式无效，尝试简单字符串匹配
                if pattern in response_text:
                    print(f"使用字符串匹配找到 '{pattern}'")
                    return pattern

        print("未找到任何SSRF特征")
        return None

    def _determine_ssrf_subtype(self, payload, match_result):
        """确定SSRF漏洞的子类型"""
        # 根据payload和匹配结果确定SSRF子类型
        if 'file:' in payload:
            return 'file_protocol'
        elif 'internal_network' in payload or '127.0.0.1' in payload or 'localhost' in payload:
            return 'internal_network'
        else:
            return 'internal_network'  # 默认子类型