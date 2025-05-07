# vuln_scan/modules/ssrf_scanner.py
import json
import aiohttp
import asyncio
import re
import time
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
        self.match_patterns = []  # 响应匹配模式
        self.rules_loaded = False  # 规则是否已加载
        self.rules_last_check = 0  # 上次检查规则的时间
        self.rules_check_interval = 300  # 规则检查间隔（秒）

        # 记录已扫描的URL，避免重复扫描
        self.scanned_urls = set()

        # 记录已发现的漏洞，避免重复报告
        self.found_vulnerabilities = set()

        # 调试日志开关
        self.debug = True

        # 创建调试日志文件
        if self.debug:
            self._init_debug_log()

    def _init_debug_log(self):
        """初始化调试日志"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.log_file = f"ssrf_scanner_debug_{timestamp}.log"
        with open(self.log_file, "w") as f:
            f.write(f"=== SSRF扫描器调试日志 - 开始于 {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")
            f.write("格式说明：\n")
            f.write("[时间] [操作类型] 详细信息\n\n")

    def _log_debug(self, operation, message):
        """记录调试日志"""
        if not self.debug:
            return

        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            with open(self.log_file, "a") as f:
                f.write(f"[{timestamp}] [{operation}] {message}\n")
        except Exception as e:
            print(f"写入调试日志失败: {str(e)}")

    def clear_cache(self):
        """清除缓存"""
        self.rules_loaded = False
        self.scanned_urls.clear()
        self.found_vulnerabilities.clear()
        self._log_debug("CLEAR_CACHE", "清除扫描器缓存")

    async def load_payloads(self):
        """从数据库加载SSRF测试载荷和匹配模式"""
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
                    self._log_debug("LOAD_RULES", f"已加载 {len(self.ssrf_payloads)} 条SSRF测试载荷")

                    # 记录所有载荷到日志
                    for i, payload in enumerate(self.ssrf_payloads):
                        self._log_debug("PAYLOAD", f"[{i + 1}] {payload}")

                    if not self.ssrf_payloads:
                        self._log_debug("WARNING", "没有从数据库加载到任何SSRF载荷")
                        return False
                except Exception as e:
                    self._log_debug("ERROR", f"解析SSRF载荷规则内容失败: {str(e)}")
                    return False
            else:
                self._log_debug("ERROR", "未找到SSRF载荷规则，无法继续扫描")
                return False

            # 加载匹配模式
            pattern_rules = await self._get_rules_by_type_and_subtype('ssrf', 'match_pattern')

            if pattern_rules:
                try:
                    rule_content = json.loads(pattern_rules[0].rule_content)
                    self.match_patterns = rule_content.get('patterns', [])
                    self._log_debug("LOAD_RULES", f"已加载 {len(self.match_patterns)} 条SSRF匹配模式")

                    # 记录所有匹配模式到日志
                    for i, pattern in enumerate(self.match_patterns):
                        self._log_debug("PATTERN", f"[{i + 1}] {pattern}")

                    if not self.match_patterns:
                        self._log_debug("WARNING", "没有从数据库加载到任何SSRF匹配模式")
                        return False
                except Exception as e:
                    self._log_debug("ERROR", f"解析SSRF匹配模式规则内容失败: {str(e)}")
                    return False
            else:
                self._log_debug("ERROR", "未找到SSRF匹配模式规则，无法继续扫描")
                return False

            # 更新规则加载状态
            self.rules_loaded = True
            self.rules_last_check = current_time
            self._log_debug("LOAD_RULES", "规则加载完成")

            return True
        except Exception as e:
            self._log_debug("ERROR", f"加载SSRF规则失败: {str(e)}")
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

            self._log_debug("DB_QUERY", f"从数据库获取 {vuln_type} 类型规则，共 {len(type_rules)} 条")

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
                    self._log_debug("ERROR", f"解析规则内容出错: {str(e)}")
                    continue

            self._log_debug("DB_QUERY", f"筛选子类型 {subtype} 后，共 {len(rules)} 条规则")
            return rules
        except Exception as e:
            self._log_debug("ERROR", f"获取规则失败: {str(e)}")
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
            self._log_debug("SCAN", "规则加载失败，跳过扫描")
            return []

        # 获取上下文数据
        asset = context['asset']
        url = context['url']
        method = context['method']
        req_headers = context['req_headers']
        req_content = context['req_content']

        self._log_debug("SCAN", f"开始扫描: {method} {url}")
        self._log_debug("SCAN_INFO", f"资产ID: {asset.id}, 主机: {asset.host}")

        # 如果URL已扫描，则跳过
        if url in self.scanned_urls:
            self._log_debug("SCAN", f"URL已扫描，跳过: {url}")
            return []

        # 标记为已扫描
        self.scanned_urls.add(url)
        self._log_debug("SCAN", f"已标记URL为已扫描: {url}")

        # 检查是否是GET或POST请求
        if method not in ['GET', 'POST']:
            self._log_debug("SCAN", f"不支持的HTTP方法: {method}，跳过扫描")
            return []

        # 准备结果
        results = []

        # 1. 检查URL参数中的SSRF
        if '?' in url:
            self._log_debug("SCAN", f"检测URL参数中的SSRF: {url}")
            url_results = await self.scan_url_parameters(context, url, self.ssrf_payloads, self.match_patterns)
            results.extend(url_results)
            self._log_debug("SCAN", f"URL参数SSRF检测完成，发现 {len(url_results)} 个漏洞")

        # 2. 检查POST请求中的SSRF
        if method == 'POST' and req_content:
            self._log_debug("SCAN", f"检测POST参数中的SSRF: {url}")
            post_results = await self.scan_post_parameters(context, url, req_content, self.ssrf_payloads,
                                                           self.match_patterns)
            results.extend(post_results)
            self._log_debug("SCAN", f"POST参数SSRF检测完成，发现 {len(post_results)} 个漏洞")

        self._log_debug("SCAN", f"扫描完成: {url}，总共发现 {len(results)} 个漏洞")
        return results

    async def scan_url_parameters(self, context, url, ssrf_payloads, match_patterns):
        """扫描URL参数中的SSRF漏洞"""
        results = []

        try:
            # 解析URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            self._log_debug("URL_SCAN", f"解析URL: {url}")
            self._log_debug("URL_SCAN", f"查询参数: {json.dumps(query_params)}")

            # 如果没有参数，直接返回
            if not query_params:
                self._log_debug("URL_SCAN", "URL没有参数，跳过扫描")
                return results

            # 创建HTTP客户端
            timeout = aiohttp.ClientTimeout(total=context.get('scan_timeout', 10))
            connector = None
            if context.get('use_proxy', False):
                connector = aiohttp.ProxyConnector.from_url(context.get('proxy_address', 'http://localhost:7890'))
                self._log_debug("URL_SCAN", f"使用代理: {context.get('proxy_address')}")
            else:
                self._log_debug("URL_SCAN", "不使用代理")

            # 测试每个参数，不做任何预设参数过滤
            for param, values in query_params.items():
                if not values:
                    continue

                original_value = values[0]
                self._log_debug("URL_SCAN", f"测试参数: {param}，原始值: {original_value}")

                # 测试每个SSRF载荷
                for payload in ssrf_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"ssrf_url_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        self._log_debug("URL_SCAN", f"跳过已发现的漏洞: {vuln_key}")
                        continue

                    # 创建测试URL - 直接替换参数值
                    test_params = query_params.copy()
                    test_params[param] = [payload]  # 直接替换为payload
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    if test_query:
                        test_url += f"?{test_query}"

                    # 构造请求数据用于日志记录
                    request_data = f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}"
                    self._log_debug("REQUEST", f"发送测试请求:\n{request_data}")

                    # 发送请求
                    try:
                        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                            start_time = time.time()
                            async with session.get(test_url) as response:
                                # 获取完整的响应文本
                                response_text = await response.text(errors='replace')
                                status = response.status
                                response_time = time.time() - start_time

                                # 记录响应信息
                                response_summary = f"HTTP/1.1 {status} - 响应时间: {response_time:.2f}秒 - 响应长度: {len(response_text)}字节"
                                self._log_debug("RESPONSE", f"收到响应: {response_summary}")

                                # 记录响应头
                                headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                                self._log_debug("RESPONSE_HEADERS", f"响应头:\n{headers_text}")

                                # 记录响应内容片段
                                content_preview = response_text[:500] + ("..." if len(response_text) > 500 else "")
                                self._log_debug("RESPONSE_CONTENT", f"响应内容预览:\n{content_preview}")

                                # 检查响应是否包含匹配模式，确定是否存在SSRF
                                match_result = self.check_ssrf_match(response_text, match_patterns)

                                if match_result:
                                    match_pattern, matched_text = match_result
                                    self._log_debug("MATCH",
                                                    f"发现匹配! 模式: {match_pattern}, 匹配文本: {matched_text}")

                                    # 构造请求数据
                                    request_data = f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}"

                                    # 构造响应数据
                                    response_data = f"HTTP/1.1 {status}\n\n{response_text[:300]}..."

                                    # 标记为已发现的漏洞
                                    self.found_vulnerabilities.add(vuln_key)
                                    self._log_debug("VULN_FOUND", f"在URL参数 {param} 中发现SSRF漏洞: {payload}")

                                    # 添加结果
                                    results.append({
                                        'vuln_type': 'ssrf',
                                        'vuln_subtype': self._determine_ssrf_subtype(payload),
                                        'name': f'URL参数 {param} 中的SSRF漏洞',
                                        'description': f'在URL参数 {param} 中发现SSRF漏洞，可以访问服务器内网或本地资源',
                                        'severity': 'high',
                                        'url': url,
                                        'request': request_data,
                                        'response': response_data,
                                        'proof': f"在URL参数 {param} 中注入 {payload} 后，响应中包含匹配特征: {matched_text}，访问结果: {match_pattern}",
                                        'parameter': param,
                                        'payload': payload
                                    })

                                    # 每个参数只添加一个结果
                                    self._log_debug("URL_SCAN", f"已为参数 {param} 添加一个结果，跳过剩余载荷测试")
                                    break
                                else:
                                    self._log_debug("MATCH", "未找到匹配")
                    except Exception as e:
                        self._log_debug("ERROR", f"测试URL参数 {param} 时出错: {str(e)}")
                        continue
        except Exception as e:
            self._log_debug("ERROR", f"扫描URL参数SSRF时出错: {str(e)}")
            import traceback
            error_trace = traceback.format_exc()
            self._log_debug("ERROR_TRACE", error_trace)

        return results

    async def scan_post_parameters(self, context, url, req_content, ssrf_payloads, match_patterns):
        """扫描POST请求参数中的SSRF漏洞"""
        results = []

        try:
            # 解析URL获取主机信息
            parsed_url = urlparse(url)
            self._log_debug("POST_SCAN", f"解析URL: {url}")

            # 检查请求内容类型并解析
            content_type = None
            for key, value in context.get('req_headers', {}).items():
                if key.lower() == 'content-type':
                    content_type = value.lower()
                    break

            self._log_debug("POST_SCAN", f"请求内容类型: {content_type}")
            self._log_debug("POST_SCAN", f"请求内容长度: {len(req_content) if req_content else 0}字节")

            post_params = {}

            # 处理不同的内容类型
            if content_type and 'application/x-www-form-urlencoded' in content_type:
                # 处理表单数据
                try:
                    post_params = parse_qs(self.safe_decode(req_content))
                    self._log_debug("POST_SCAN", f"解析表单数据: {json.dumps(post_params)}")
                except Exception as e:
                    self._log_debug("ERROR", f"解析表单数据时出错: {str(e)}")
            elif content_type and 'application/json' in content_type:
                # 处理JSON数据
                try:
                    json_data = json.loads(self.safe_decode(req_content))
                    self._log_debug("POST_SCAN", f"解析JSON数据: {json.dumps(json_data)}")

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

                    flattened = flatten_json(json_data)
                    self._log_debug("POST_SCAN", f"扁平化JSON: {json.dumps(flattened)}")

                    # 转换为与parse_qs相同的格式 {param: [value]}
                    post_params = {k: [v] for k, v in flattened.items()}
                except Exception as e:
                    self._log_debug("ERROR", f"解析JSON数据时出错: {str(e)}")
            else:
                # 尝试直接解析为表单数据
                try:
                    post_params = parse_qs(self.safe_decode(req_content))
                    self._log_debug("POST_SCAN", f"尝试解析为默认表单数据: {json.dumps(post_params)}")
                except Exception as e:
                    self._log_debug("ERROR", f"解析未知类型的请求内容时出错: {str(e)}")

            # 如果没有参数，直接返回
            if not post_params:
                self._log_debug("POST_SCAN", "POST请求没有参数，跳过扫描")
                return results

            # 创建HTTP客户端
            timeout = aiohttp.ClientTimeout(total=context.get('scan_timeout', 10))
            connector = None
            if context.get('use_proxy', False):
                connector = aiohttp.ProxyConnector.from_url(context.get('proxy_address', 'http://localhost:7890'))
                self._log_debug("POST_SCAN", f"使用代理: {context.get('proxy_address')}")
            else:
                self._log_debug("POST_SCAN", "不使用代理")

            # 测试每个参数，不做任何预设参数过滤
            for param, values in post_params.items():
                if not values:
                    continue

                original_value = values[0]
                self._log_debug("POST_SCAN", f"测试参数: {param}，原始值: {original_value}")

                # 测试每个SSRF载荷
                for payload in ssrf_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"ssrf_post_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        self._log_debug("POST_SCAN", f"跳过已发现的漏洞: {vuln_key}")
                        continue

                    # 创建测试参数 - 直接替换参数值
                    test_params = post_params.copy()
                    test_params[param] = [payload]  # 直接替换为payload
                    self._log_debug("POST_SCAN", f"替换参数值: {param} = {payload}")

                    # 根据content_type准备请求内容
                    if content_type and 'application/json' in content_type:
                        # 将扁平的参数还原为JSON
                        test_json = {}
                        for k, v in test_params.items():
                            # 简单处理，仅支持顶级键
                            test_json[k] = v[0]
                        test_content = json.dumps(test_json)
                        headers = {'Content-Type': 'application/json'}
                        self._log_debug("POST_SCAN", f"生成JSON请求体: {test_content}")
                    else:
                        # 默认使用表单格式
                        test_content = urlencode(test_params, doseq=True)
                        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                        self._log_debug("POST_SCAN", f"生成表单请求体: {test_content}")

                    # 构造完整的HTTP请求用于日志
                    request_data = f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {headers['Content-Type']}\nContent-Length: {len(test_content)}\n\n{test_content}"
                    self._log_debug("REQUEST", f"发送测试请求:\n{request_data}")

                    # 发送请求
                    try:
                        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                            start_time = time.time()
                            async with session.post(url, data=test_content, headers=headers) as response:
                                # 获取完整的响应文本
                                response_text = await response.text(errors='replace')
                                status = response.status
                                response_time = time.time() - start_time

                                # 记录响应信息
                                response_summary = f"HTTP/1.1 {status} - 响应时间: {response_time:.2f}秒 - 响应长度: {len(response_text)}字节"
                                self._log_debug("RESPONSE", f"收到响应: {response_summary}")

                                # 记录响应头
                                headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                                self._log_debug("RESPONSE_HEADERS", f"响应头:\n{headers_text}")

                                # 记录响应内容片段
                                content_preview = response_text[:500] + ("..." if len(response_text) > 500 else "")
                                self._log_debug("RESPONSE_CONTENT", f"响应内容预览:\n{content_preview}")

                                # 检查响应是否包含匹配模式，确定是否存在SSRF
                                match_result = self.check_ssrf_match(response_text, match_patterns)

                                if match_result:
                                    match_pattern, matched_text = match_result
                                    self._log_debug("MATCH",
                                                    f"发现匹配! 模式: {match_pattern}, 匹配文本: {matched_text}")

                                    # 构造请求数据
                                    request_data = f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {headers['Content-Type']}\n\n{test_content}"

                                    # 构造响应数据
                                    response_data = f"HTTP/1.1 {status}\n\n{response_text[:300]}..."

                                    # 标记为已发现的漏洞
                                    self.found_vulnerabilities.add(vuln_key)
                                    self._log_debug("VULN_FOUND", f"在POST参数 {param} 中发现SSRF漏洞: {payload}")

                                    # 添加结果
                                    results.append({
                                        'vuln_type': 'ssrf',
                                        'vuln_subtype': self._determine_ssrf_subtype(payload),
                                        'name': f'POST参数 {param} 中的SSRF漏洞',
                                        'description': f'在POST参数 {param} 中发现SSRF漏洞，可以访问服务器内网或本地资源',
                                        'severity': 'high',
                                        'url': url,
                                        'request': request_data,
                                        'response': response_data,
                                        'proof': f"在POST参数 {param} 中注入 {payload} 后，响应中包含匹配特征: {matched_text}，访问结果: {match_pattern}",
                                        'parameter': param,
                                        'payload': payload
                                    })

                                    # 每个参数只添加一个结果
                                    self._log_debug("POST_SCAN", f"已为参数 {param} 添加一个结果，跳过剩余载荷测试")
                                    break
                                else:
                                    self._log_debug("MATCH", "未找到匹配")
                    except Exception as e:
                        self._log_debug("ERROR", f"测试POST参数 {param} 时出错: {str(e)}")
                        continue
        except Exception as e:
            self._log_debug("ERROR", f"扫描POST参数SSRF时出错: {str(e)}")
            import traceback
            error_trace = traceback.format_exc()
            self._log_debug("ERROR_TRACE", error_trace)

        return results

    def check_ssrf_match(self, response_text, match_patterns):
        """
        检查响应是否存在SSRF的特征匹配

        返回:
            如果匹配成功，返回 (匹配模式, 匹配的文本)
            如果不匹配，返回 None
        """
        if not response_text or not match_patterns:
            return None

        for pattern in match_patterns:
            try:
                # 尝试使用正则表达式匹配
                regex = re.compile(pattern, re.IGNORECASE)
                match = regex.search(response_text)
                if match:
                    return (pattern, match.group(0))
            except re.error:
                # 如果正则表达式无效，使用简单的字符串匹配
                if pattern in response_text:
                    return (pattern, pattern)

        return None

    def _determine_ssrf_subtype(self, payload):
        """确定SSRF漏洞的子类型"""
        # 根据payload确定SSRF子类型
        if 'file:' in payload:
            return 'file_protocol'
        elif any(term in payload.lower() for term in ['127.0.0.1', 'localhost', '192.168.', '10.']):
            return 'internal_network'
        elif any(term in payload.lower() for term in ['burpcollaborator.net', 'dnslog', 'xip.io', 'callback']):
            return 'blind_ssrf'
        elif 'dns-rebind' in payload.lower() or 'rebinding' in payload.lower():
            return 'dns_rebinding'
        else:
            return 'general_ssrf'  # 通用SSRF