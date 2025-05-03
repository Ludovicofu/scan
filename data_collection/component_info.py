import asyncio
import aiohttp
import re
import json
from urllib.parse import urlparse, urljoin


class ComponentInfoScanner:
    """
    组件与服务信息扫描模块：负责扫描网站使用的组件和服务
    """

    def __init__(self):
        """初始化扫描器"""
        # 不再使用硬编码的特征指纹
        # 而是动态从规则中获取
        self.signatures = {}

    def safe_decode(self, value):
        """
        安全地解码任何值，处理所有可能的编码错误
        增强处理二进制数据的能力
        """
        if value is None:
            return ""

        if isinstance(value, bytes):
            try:
                # 首先尝试UTF-8解码
                return value.decode('utf-8', errors='replace')
            except Exception:
                try:
                    # 尝试其他编码
                    for encoding in ['latin1', 'gbk', 'gb2312', 'ascii']:
                        try:
                            return value.decode(encoding, errors='replace')
                        except:
                            continue

                    # 如果所有解码都失败，转为十六进制表示
                    return f"[二进制数据: {value.hex()[:30]}...]"
                except:
                    # 最后的兜底方案
                    return "[解码失败的二进制数据]"

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

    async def scan(self, url, behavior, rule_type, match_values, use_proxy=False, proxy_address=None):
        """
        根据规则扫描组件与服务信息

        参数:
            url: 目标URL
            behavior: 扫描行为
            rule_type: 规则类型 (status_code, response_content, header)
            match_values: 匹配值列表
            use_proxy: 是否使用代理
            proxy_address: 代理地址

        返回:
            匹配结果字典，如果没有匹配则返回None
        """
        # 日志记录和参数验证
        print(f"组件扫描参数: URL={url}, 行为={behavior}, 规则类型={rule_type}")
        if not match_values or len(match_values) == 0:
            print(f"警告: 没有提供匹配值，跳过组件扫描")
            return None

        # 解析原始URL，获取基本域名和协议
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # 构建目标URL（基本URL + 行为路径）
        target_url = urljoin(base_url, behavior)

        # 设置代理
        proxy = None
        if use_proxy and proxy_address:
            proxy = proxy_address

        # 构建请求头
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'close',
        }

        try:
            # 创建异步HTTP会话
            async with aiohttp.ClientSession() as session:
                # 发送请求
                async with session.get(
                        target_url,
                        headers=headers,
                        proxy=proxy,
                        ssl=False,  # 忽略SSL证书验证
                        timeout=aiohttp.ClientTimeout(total=10)  # 设置超时
                ) as response:
                    # 获取响应状态码
                    status_code = response.status

                    # 获取响应头 - 使用安全解码
                    resp_headers = {}
                    for key, value in response.headers.items():
                        safe_key = self.safe_decode(key)
                        safe_value = self.safe_decode(value)

                        # 跳过解码失败的头部
                        if "[解码失败" in safe_key or "[二进制数据" in safe_key:
                            continue
                        if "[解码失败" in safe_value or "[二进制数据" in safe_value:
                            safe_value = "[二进制内容]"

                        resp_headers[safe_key] = safe_value

                    # 获取响应内容
                    resp_content = await response.text(errors='replace')

                    # 根据规则类型进行匹配
                    if rule_type == 'status_code':
                        # 状态码判断
                        if str(status_code) in match_values:
                            return {'match_value': str(status_code)}

                    elif rule_type == 'response_content':
                        # 响应内容匹配
                        for match_value in match_values:
                            if match_value.lower() in resp_content.lower():
                                return {'match_value': match_value}

                    elif rule_type == 'header':
                        # HTTP头匹配 - 添加更多的安全检查
                        for match_value in match_values:
                            try:
                                # 安全解析匹配值
                                if ':' in match_value:
                                    header_parts = match_value.split(':', 1)
                                    header_name = header_parts[0].strip()
                                    header_value = header_parts[1].strip() if len(header_parts) > 1 else ''
                                else:
                                    header_name = match_value.strip()
                                    header_value = ''

                                # 检查头名称是否有效
                                if not header_name or header_name in ["[编码错误]", "[二进制数据", "[解码失败"]:
                                    print(f"无效的HTTP头名称: {header_name}")
                                    continue

                                # 检查头是否存在
                                if header_name in resp_headers:
                                    actual_value = resp_headers[header_name]

                                    # 跳过二进制内容
                                    if actual_value == "[二进制内容]":
                                        continue

                                    # 如果没有指定值，或者值包含在实际值中
                                    if not header_value or (header_value.lower() in actual_value.lower()):
                                        return {'match_value': match_value}
                            except Exception as e:
                                print(f"处理HTTP头匹配值时出错: {str(e)}")
                                continue

            # 没有匹配结果
            return None

        except aiohttp.ClientConnectorError as e:
            # 连接错误，可能是端口关闭
            print(f"连接错误: {str(e)}")
            return None
        except aiohttp.ClientError as e:
            # 其他HTTP客户端错误
            print(f"HTTP客户端错误: {str(e)}")
            return None
        except asyncio.TimeoutError:
            # 请求超时
            print(f"请求超时")
            return None
        except Exception as e:
            # 其他错误
            print(f"组件与服务信息扫描出错: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    async def detect_components(self, url, use_proxy=False, proxy_address=None, signatures=None):
        """
        检测网站使用的组件和服务

        参数:
            url: 目标URL
            use_proxy: 是否使用代理
            proxy_address: 代理地址
            signatures: 组件特征签名，如果为None则使用默认配置

        返回:
            检测到的组件列表
        """
        # 如果没有提供特征签名，则使用默认的空字典
        if signatures is None:
            print("警告: 没有提供组件特征签名")
            return []

        # 解析原始URL
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # 设置代理
        proxy = None
        if use_proxy and proxy_address:
            proxy = proxy_address

        # 构建请求头
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'close',
        }

        detected_components = []

        try:
            # 创建异步HTTP会话
            async with aiohttp.ClientSession() as session:
                # 首先请求主页
                async with session.get(
                        base_url,
                        headers=headers,
                        proxy=proxy,
                        ssl=False,
                        timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    # 获取响应头 - 使用安全解码
                    resp_headers = {}
                    for key, value in response.headers.items():
                        safe_key = self.safe_decode(key)
                        safe_value = self.safe_decode(value)

                        # 跳过无法解码的头部
                        if "[解码失败" in safe_key or "[二进制数据" in safe_key:
                            continue
                        if "[解码失败" in safe_value or "[二进制数据" in safe_value:
                            safe_value = "[二进制内容]"

                        resp_headers[safe_key] = safe_value

                    # 获取响应内容
                    resp_content = await response.text(errors='replace')

                    # 检查每个组件的特征指纹
                    for component, component_signatures in signatures.items():
                        for signature in component_signatures:
                            try:
                                # 验证签名格式
                                if not isinstance(signature, dict) or 'type' not in signature:
                                    print(f"无效的特征签名格式: {signature}")
                                    continue

                                sig_type = signature.get('type')

                                if sig_type == 'header':
                                    # 检查HTTP头
                                    header_name = signature.get('name')
                                    header_value = signature.get('value', '')

                                    if not header_name:
                                        print(f"无效的HTTP头名称: {header_name}")
                                        continue

                                    # 检查头名称是否有效
                                    if header_name in ["[编码错误]", "[二进制数据", "[解码失败"]:
                                        continue

                                    # 安全检查头部
                                    if header_name in resp_headers:
                                        actual_value = resp_headers[header_name]

                                        # 跳过二进制内容
                                        if actual_value == "[二进制内容]":
                                            continue

                                        if not header_value or header_value.lower() in actual_value.lower():
                                            if component not in detected_components:
                                                detected_components.append(component)
                                                print(f"通过HTTP头 {header_name} 检测到组件: {component}")

                                elif sig_type == 'content':
                                    # 检查响应内容
                                    content_value = signature.get('value')

                                    if not content_value:
                                        continue

                                    if content_value.lower() in resp_content.lower():
                                        if component not in detected_components:
                                            detected_components.append(component)
                                            print(f"通过内容匹配 '{content_value}' 检测到组件: {component}")
                            except Exception as e:
                                print(f"处理组件特征时出错: {str(e)}")
                                continue

                # 请求特定路径
                for component, component_signatures in signatures.items():
                    for signature in component_signatures:
                        try:
                            if signature.get('type') == 'path':
                                path_value = signature.get('value')
                                if not path_value:
                                    continue

                                path_url = urljoin(base_url, path_value)

                                try:
                                    async with session.get(
                                            path_url,
                                            headers=headers,
                                            proxy=proxy,
                                            ssl=False,
                                            timeout=aiohttp.ClientTimeout(total=5)
                                    ) as path_response:
                                        # 如果请求成功（状态码200），则认为检测到了组件
                                        if path_response.status == 200:
                                            if component not in detected_components:
                                                detected_components.append(component)
                                                print(f"通过路径 {path_value} 检测到组件: {component}")

                                except Exception as path_error:
                                    # 忽略路径请求错误
                                    continue
                        except Exception as e:
                            print(f"处理路径特征时出错: {str(e)}")
                            continue

        except Exception as e:
            # 扫描出错
            print(f"组件检测出错: {str(e)}")
            import traceback
            traceback.print_exc()

        return detected_components

    async def load_signatures_from_config(self, config_file=None):
        """
        从配置文件中加载组件特征签名

        参数:
            config_file: 配置文件路径

        返回:
            加载的特征签名字典
        """
        # 这里可以实现从配置文件加载特征签名的逻辑
        # 如果没有提供配置文件，则返回空字典
        if not config_file:
            return {}

        try:
            # 从JSON文件加载配置
            with open(config_file, 'r', encoding='utf-8') as f:
                signatures = json.load(f)
            return signatures
        except Exception as e:
            print(f"加载组件特征签名配置文件失败: {str(e)}")
            return {}