# vuln_scan/modules/rce_scanner.py
import json
import re
import aiohttp
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from asgiref.sync import sync_to_async
from rules.models import VulnScanRule


class RceScanner:
    """
    命令执行扫描器：检测命令注入(Command Injection)和代码执行(Code Execution)漏洞
    """

    def __init__(self):
        """初始化扫描器"""
        self.rce_payloads = []  # 命令/代码执行测试载荷
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
        print("RCE扫描器缓存已清除")

    async def load_payloads(self):
        """
        从数据库加载RCE测试载荷和匹配模式
        如果没有规则，返回False，跳过扫描
        """
        try:
            print("开始加载RCE规则...")
            current_time = asyncio.get_event_loop().time()

            # 如果规则已加载且未超过检查间隔，则跳过
            if self.rules_loaded and (current_time - self.rules_last_check < self.rules_check_interval):
                print("规则已经加载且未超过检查间隔，跳过重新加载")
                return True

            # 加载命令/代码执行载荷
            print("尝试获取RCE载荷规则...")
            payload_rules = await self._get_rules_by_type_and_subtype('command_injection', 'payload')

            if payload_rules:
                try:
                    rule_content = json.loads(payload_rules[0].rule_content)
                    self.rce_payloads = rule_content.get('payloads', [])
                    print(f"已加载 {len(self.rce_payloads)} 条命令/代码执行载荷")
                except Exception as e:
                    print(f"解析载荷规则失败: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    self.rce_payloads = []
            else:
                print("未找到命令/代码执行载荷规则，不执行RCE扫描")
                self.rce_payloads = []

            # 加载匹配模式
            print("尝试获取RCE匹配模式规则...")
            pattern_rules = await self._get_rules_by_type_and_subtype('command_injection', 'match_pattern')

            if pattern_rules:
                try:
                    rule_content = json.loads(pattern_rules[0].rule_content)
                    # 尝试多种可能的键名
                    self.match_patterns = rule_content.get('patterns', [])
                    if not self.match_patterns:
                        self.match_patterns = rule_content.get('payloads', [])
                    if not self.match_patterns and 'rule_content' in rule_content:
                        # 处理嵌套的rule_content情况
                        nested_content = rule_content.get('rule_content', {})
                        if isinstance(nested_content, str):
                            try:
                                nested_content = json.loads(nested_content)
                            except:
                                pass
                        if isinstance(nested_content, dict):
                            self.match_patterns = nested_content.get('patterns', [])
                            if not self.match_patterns:
                                self.match_patterns = nested_content.get('payloads', [])

                    print(f"已加载 {len(self.match_patterns)} 条命令/代码执行匹配模式")
                except Exception as e:
                    print(f"解析匹配模式规则失败: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    self.match_patterns = []
            else:
                print("未找到命令/代码执行匹配模式规则，不执行RCE扫描")
                self.match_patterns = []

            # 更新规则加载状态
            self.rules_loaded = True
            self.rules_last_check = current_time

            # 如果没有任何规则，返回False
            if not self.rce_payloads or not self.match_patterns:
                print("命令/代码执行规则不完整，跳过RCE扫描")
                return False

            print("RCE规则加载成功")
            return True
        except Exception as e:
            print(f"加载命令/代码执行规则失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    @sync_to_async
    def _get_rules_by_type_and_subtype(self, vuln_type, subtype):
        """获取指定类型和子类型的规则"""
        try:
            print(f"正在从数据库获取规则，类型: {vuln_type}，子类型: {subtype}")
            rules = []
            # 获取指定类型的规则
            type_rules = VulnScanRule.objects.filter(
                vuln_type=vuln_type,
                is_enabled=True
            )

            print(f"查询到 {len(type_rules)} 条类型为 {vuln_type} 的规则")

            # 从规则内容中筛选子类型
            for i, rule in enumerate(type_rules):
                try:
                    print(f"解析规则 {i + 1}, ID: {rule.id}, 名称: {rule.name}")

                    rule_content = json.loads(rule.rule_content)
                    rule_subtype = rule_content.get('subType')
                    print(f"规则子类型: {rule_subtype}")

                    if rule_subtype == subtype:
                        rules.append(rule)
                        print(f"已添加匹配的规则，ID: {rule.id}")
                except json.JSONDecodeError as json_err:
                    print(f"规则JSON解析错误: {str(json_err)}")

                    # 如果JSON解析失败，尝试字符串匹配
                    if f'"subType": "{subtype}"' in rule.rule_content or f'"subType":"{subtype}"' in rule.rule_content:
                        rules.append(rule)
                        print(f"通过字符串匹配添加规则，ID: {rule.id}")
                except Exception as e:
                    print(f"解析规则内容出错: {str(e)}")
                    continue

            print(f"最终匹配到 {len(rules)} 条规则")
            return rules
        except Exception as e:
            print(f"获取规则失败: {str(e)}")
            import traceback
            traceback.print_exc()
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
        """执行RCE扫描"""
        # 加载规则，如果没有规则则跳过扫描
        print(f"开始RCE扫描，URL: {context.get('url', 'Unknown')}")
        rules_loaded = await self.load_payloads()
        if not rules_loaded:
            print("RCE规则加载失败，跳过扫描")
            return []

        # 获取上下文数据
        asset = context['asset']
        url = context['url']
        method = context['method']
        req_headers = context['req_headers']
        req_content = context['req_content']
        resp_headers = context['resp_headers']
        resp_content = context['resp_content']

        print(f"开始扫描URL: {url}, 方法: {method}")
        print(f"资产ID: {asset.id}, 主机: {asset.host}")

        # 如果URL已扫描，则跳过
        if url in self.scanned_urls:
            print(f"URL已扫描，跳过: {url}")
            return []

        # 标记为已扫描
        self.scanned_urls.add(url)
        print(f"已标记URL为已扫描: {url}")

        # 检查是否是GET或POST请求
        if method not in ['GET', 'POST']:
            print(f"不支持的HTTP方法: {method}，跳过扫描")
            return []

        # 准备结果
        results = []

        # 1. 检查URL参数中的RCE
        if '?' in url:
            print(f"检测URL参数中的RCE: {url}")
            url_results = await self.scan_url_parameters(context, url, self.rce_payloads, self.match_patterns)
            results.extend(url_results)
            print(f"URL参数RCE检测完成，发现 {len(url_results)} 个漏洞")

        # 2. 检查POST请求中的RCE
        if method == 'POST' and req_content:
            print(f"检测POST参数中的RCE: {url}")
            post_results = await self.scan_post_parameters(context, url, req_content, self.rce_payloads,
                                                           self.match_patterns)
            results.extend(post_results)
            print(f"POST参数RCE检测完成，发现 {len(post_results)} 个漏洞")

        print(f"扫描完成: {url}，总共发现 {len(results)} 个漏洞")
        return results

    async def scan_url_parameters(self, context, url, rce_payloads, match_patterns):
        """扫描URL参数中的RCE漏洞"""
        results = []

        try:
            # 解析URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            print(f"解析URL: {url}")
            print(f"查询参数: {query_params}")

            # 如果没有参数，直接返回
            if not query_params:
                print("URL没有参数，跳过扫描")
                return results

            # 创建HTTP客户端
            timeout = aiohttp.ClientTimeout(total=context.get('scan_timeout', 10))
            connector = None
            if context.get('use_proxy', False):
                connector = aiohttp.ProxyConnector.from_url(context.get('proxy_address', 'http://localhost:7890'))
                print(f"使用代理: {context.get('proxy_address')}")
            else:
                print("不使用代理")

            # 测试每个参数
            for param, values in query_params.items():
                if not values:
                    continue

                original_value = values[0]
                print(f"测试参数: {param}，原始值: {original_value}")

                # 测试每个RCE载荷
                for payload in rce_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"rce_url_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        print(f"跳过已发现的漏洞: {vuln_key}")
                        continue

                    # 创建测试URL
                    test_params = query_params.copy()
                    test_params[param] = [original_value + payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    if test_query:
                        test_url += f"?{test_query}"

                    print(f"测试载荷: {payload}")
                    print(f"测试URL: {test_url}")

                    # 发送请求
                    try:
                        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                            print(f"发送GET请求: {test_url}")
                            start_time = asyncio.get_event_loop().time()

                            async with session.get(test_url) as response:
                                response_time = asyncio.get_event_loop().time() - start_time
                                status = response.status
                                print(f"状态码: {status}, 响应时间: {response_time:.2f}秒")

                                # 获取头信息
                                headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                                print(f"响应头:\n{headers_text[:500]}")

                                response_text = await response.text(errors='replace')
                                print(f"响应长度: {len(response_text)}字节")

                                # 记录响应内容片段
                                content_preview = response_text[:500] + ("..." if len(response_text) > 500 else "")
                                print(f"响应内容预览:\n{content_preview}")

                                # 检查是否存在RCE特征
                                rce_match = self.check_rce_match(response_text, match_patterns)
                                if rce_match:
                                    print(f"发现匹配项: {rce_match}")

                                    # 构造请求数据
                                    request_data = f"GET {test_url} HTTP/1.1\nHost: {parsed_url.netloc}"

                                    # 构造响应数据
                                    response_data = f"HTTP/1.1 {status}\n\n{response_text[:300]}..."

                                    # 构造证明数据
                                    proof = f"在URL参数 {param} 中注入 {payload} 后，响应中包含匹配特征: {rce_match}"

                                    # 标记为已发现的漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 添加结果
                                    results.append({
                                        'vuln_type': 'command_injection',
                                        'vuln_subtype': 'os_command',  # 默认子类型
                                        'name': f'URL参数 {param} 中的命令执行漏洞',
                                        'description': f'在URL参数 {param} 中发现命令执行漏洞，可以执行任意系统命令',
                                        'severity': 'high',
                                        'url': url,
                                        'request': request_data,
                                        'response': response_data,
                                        'proof': f"{proof}，执行结果: {rce_match}",
                                        'parameter': param,
                                        'payload': payload
                                    })

                                    print(f"在URL参数 {param} 中发现RCE漏洞")
                                    # 每个参数只添加一个结果
                                    break
                                else:
                                    print(f"未找到匹配项，已尝试 {len(match_patterns)} 个匹配模式")
                    except Exception as e:
                        print(f"测试URL参数 {param} 的RCE漏洞时出错: {str(e)}")
                        import traceback
                        traceback.print_exc()
                        continue
        except Exception as e:
            print(f"扫描URL参数RCE时出错: {str(e)}")
            import traceback
            traceback.print_exc()

        return results

    async def scan_post_parameters(self, context, url, req_content, rce_payloads, match_patterns):
        """扫描POST请求参数中的RCE漏洞"""
        results = []

        try:
            # 解析URL获取主机信息
            parsed_url = urlparse(url)
            print(f"解析URL: {url}")

            # 检查请求内容类型并解析
            content_type = None
            for key, value in context.get('req_headers', {}).items():
                if key.lower() == 'content-type':
                    content_type = value.lower()
                    break

            print(f"请求内容类型: {content_type}")
            print(f"请求内容长度: {len(req_content) if req_content else 0}字节")

            post_params = {}
            decoded_content = self.safe_decode(req_content)
            print(f"请求内容预览: {decoded_content[:100]}...")

            # 处理不同的内容类型
            if content_type and 'application/x-www-form-urlencoded' in content_type:
                # 处理表单数据
                try:
                    post_params = parse_qs(decoded_content)
                    print(f"解析表单数据: {post_params}")
                except Exception as e:
                    print(f"解析表单数据时出错: {str(e)}")
            elif content_type and 'application/json' in content_type:
                # 处理JSON数据
                try:
                    json_data = json.loads(decoded_content)
                    print(f"解析JSON数据: {json_data}")

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
                    print(f"扁平化JSON: {flattened}")

                    # 转换为与parse_qs相同的格式 {param: [value]}
                    post_params = {k: [v] for k, v in flattened.items()}
                except Exception as e:
                    print(f"解析JSON数据时出错: {str(e)}")
            else:
                # 尝试直接解析为表单数据
                try:
                    post_params = parse_qs(decoded_content)
                    print(f"尝试解析为默认表单数据: {post_params}")
                except Exception as e:
                    print(f"解析未知类型的请求内容时出错: {str(e)}")

            # 如果没有参数，直接返回
            if not post_params:
                print("POST请求没有参数，跳过扫描")
                return results

            # 创建HTTP客户端
            timeout = aiohttp.ClientTimeout(total=context.get('scan_timeout', 10))
            connector = None
            if context.get('use_proxy', False):
                connector = aiohttp.ProxyConnector.from_url(context.get('proxy_address', 'http://localhost:7890'))
                print(f"使用代理: {context.get('proxy_address')}")
            else:
                print("不使用代理")

            # 测试每个参数
            for param, values in post_params.items():
                if not values:
                    continue

                original_value = values[0]
                print(f"测试参数: {param}，原始值: {original_value}")

                # 测试每个RCE载荷
                for payload in rce_payloads:
                    # 检测是否已存在相同漏洞
                    vuln_key = f"rce_post_{param}_{url}"
                    if vuln_key in self.found_vulnerabilities:
                        print(f"跳过已发现的漏洞: {vuln_key}")
                        continue

                    # 创建测试参数
                    test_params = post_params.copy()
                    test_params[param] = [original_value + payload]
                    print(f"测试载荷: {payload}")

                    # 根据content_type准备请求内容
                    if content_type and 'application/json' in content_type:
                        # 将扁平的参数还原为JSON
                        test_json = {}
                        for k, v in test_params.items():
                            # 简单处理，仅支持顶级键
                            test_json[k] = v[0]
                        test_content = json.dumps(test_json)
                        headers = {'Content-Type': 'application/json'}
                        print(f"生成JSON请求体: {test_content}")
                    else:
                        # 默认使用表单格式
                        test_content = urlencode(test_params, doseq=True)
                        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                        print(f"生成表单请求体: {test_content}")

                    # 发送请求
                    try:
                        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                            print(f"发送POST请求: {url}")
                            print(f"请求头: {headers}")
                            print(f"请求体: {test_content}")

                            start_time = asyncio.get_event_loop().time()
                            async with session.post(url, data=test_content, headers=headers) as response:
                                response_time = asyncio.get_event_loop().time() - start_time
                                status = response.status
                                print(f"状态码: {status}, 响应时间: {response_time:.2f}秒")

                                # 获取头信息
                                headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                                print(f"响应头:\n{headers_text[:500]}")

                                response_text = await response.text(errors='replace')
                                print(f"响应长度: {len(response_text)}字节")

                                # 记录响应内容片段
                                content_preview = response_text[:500] + ("..." if len(response_text) > 500 else "")
                                print(f"响应内容预览:\n{content_preview}")

                                # 检查是否存在RCE特征
                                rce_match = self.check_rce_match(response_text, match_patterns)
                                if rce_match:
                                    print(f"发现匹配项: {rce_match}")

                                    # 构造请求数据
                                    request_data = f"POST {url} HTTP/1.1\nHost: {parsed_url.netloc}\nContent-Type: {headers['Content-Type']}\n\n{test_content}"

                                    # 构造响应数据
                                    response_data = f"HTTP/1.1 {status}\n\n{response_text[:300]}..."

                                    # 构造证明数据
                                    proof = f"在POST参数 {param} 中注入 {payload} 后，响应中包含匹配特征: {rce_match}"

                                    # 标记为已发现的漏洞
                                    self.found_vulnerabilities.add(vuln_key)

                                    # 确定漏洞子类型
                                    vuln_subtype = 'os_command'  # 默认为系统命令注入
                                    if '${' in payload or '{' in payload or 'eval' in payload or 'exec' in payload:
                                        vuln_subtype = 'php_code'  # PHP代码注入
                                    elif '__import__' in payload or 'print(' in payload:
                                        vuln_subtype = 'python_code'  # Python代码注入
                                    elif 'System.out' in payload or 'Runtime.getRuntime' in payload:
                                        vuln_subtype = 'java_code'  # Java代码注入

                                    # 添加结果
                                    results.append({
                                        'vuln_type': 'command_injection',
                                        'vuln_subtype': vuln_subtype,
                                        'name': f'POST参数 {param} 中的命令/代码执行漏洞',
                                        'description': f'在POST参数 {param} 中发现命令/代码执行漏洞，可以执行任意命令或代码',
                                        'severity': 'high',
                                        'url': url,
                                        'request': request_data,
                                        'response': response_data,
                                        'proof': f"{proof}，执行结果: {rce_match}",
                                        'parameter': param,
                                        'payload': payload
                                    })

                                    print(f"在POST参数 {param} 中发现RCE漏洞")
                                    # 每个参数只添加一个结果
                                    break
                                else:
                                    print(f"未找到匹配项，已尝试 {len(match_patterns)} 个匹配模式")
                    except Exception as e:
                        print(f"测试POST参数 {param} 时出错: {str(e)}")
                        import traceback
                        traceback.print_exc()
                        continue
        except Exception as e:
            print(f"扫描POST参数RCE时出错: {str(e)}")
            import traceback
            traceback.print_exc()

        return results

    def check_rce_match(self, response_text, match_patterns):
        """检查响应中是否包含RCE执行结果的特征"""
        if not response_text or not match_patterns:
            print("响应文本为空或没有匹配模式")
            return None

        # 打印响应文本的前500个字符，便于调试
        preview = response_text[:500] + ("..." if len(response_text) > 500 else "")
        print(f"响应内容预览：{preview}")
        print(f"开始检查 {len(match_patterns)} 个匹配模式")

        # 对每个匹配模式进行检查
        for pattern in match_patterns:
            try:
                print(f"尝试匹配模式: {pattern}")

                # 尝试正则表达式匹配
                try:
                    regex = re.compile(pattern, re.IGNORECASE)
                    match = regex.search(response_text)
                    if match:
                        matched_text = match.group(0)
                        print(f"正则表达式匹配成功: 模式={pattern}, 匹配文本={matched_text}")
                        return matched_text
                except re.error as regex_err:
                    print(f"正则表达式错误: {str(regex_err)}, 将尝试字符串匹配")
                    # 正则表达式出错，尝试简单字符串匹配
                    pass

                # 如果正则表达式未匹配或出错，尝试简单字符串匹配
                if pattern in response_text:
                    print(f"字符串匹配成功: {pattern}")
                    return pattern
                else:
                    print(f"字符串匹配失败: {pattern}")

            except Exception as e:
                print(f"匹配过程出错: {str(e)}")
                import traceback
                traceback.print_exc()

        print("所有模式均未匹配")
        return None