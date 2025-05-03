import json
import time
import base64
import requests
from mitmproxy import http, ctx


class Proxy:
    """
    mitmproxy脚本，用于监听HTTP流量并发送到后端接口
    """

    def __init__(self):
        self.backend_url = "http://localhost:8000/proxy/"
        self.timeout = 10  # 增加超时时间，单位为秒
        self.use_proxy = False
        self.proxy_url = "http://localhost:7890"
        self.skip_targets = set()  # 要跳过的目标列表
        self.max_content_size = 50000  # 最大内容大小，超过则截断

    def load(self, loader):
        """初始化加载"""
        ctx.log.info("被动代理漏洞扫描系统代理已启动！监听端口：7891")

    def request(self, flow: http.HTTPFlow) -> None:
        """捕获请求"""
        # 记录请求时间，用于计算响应时间
        flow.request.timestamp_start = time.time()

    def response(self, flow: http.HTTPFlow) -> None:
        """捕获响应并将数据发送到后端"""
        try:
            # 处理CONNECT请求
            if flow.request.method == "CONNECT":
                # 对于CONNECT请求，我们只记录不处理
                ctx.log.info(f"CONNECT请求: {flow.request.host}")
                return

            # 如果目标在跳过列表中，则不处理
            host = flow.request.host
            if host in self.skip_targets:
                return

            # 计算响应时间
            response_time = int((time.time() - flow.request.timestamp_start) * 1000)  # 毫秒

            # 安全地处理请求头，确保编码正确
            req_headers = self._safely_process_headers(flow.request.headers)
            resp_headers = self._safely_process_headers(flow.response.headers)

            # 获取请求内容，可能是二进制数据
            req_content = self._safely_decode_content(flow.request.content)

            # 获取响应内容，可能是二进制数据
            resp_content = self._safely_decode_content(flow.response.content)

            # 准备要发送的数据
            data = {
                "url": flow.request.url,
                "method": flow.request.method,
                "req_headers": req_headers,
                "req_content": req_content,
                "status_code": flow.response.status_code,
                "resp_headers": resp_headers,
                "resp_content": resp_content,
                "response_time": response_time
            }

            # 使用非阻塞方式发送数据到后端
            ctx.log.info(f"发送数据到后端: {data['url']}, 状态码: {data['status_code']}")
            self._send_to_backend_nonblocking(data)
        except Exception as e:
            ctx.log.warn(f"处理响应数据时出错: {str(e)}")
            import traceback
            traceback.print_exc()

    def _safely_process_headers(self, headers):
        """
        安全地处理HTTP头，确保所有值都是有效的UTF-8字符串

        参数:
            headers: HTTP头字典

        返回:
            处理后的HTTP头字典
        """
        processed_headers = {}

        for key, value in headers.items():
            # 处理键
            if isinstance(key, bytes):
                try:
                    key = key.decode('utf-8')
                except UnicodeDecodeError:
                    key = key.decode('utf-8', errors='replace')

            # 处理值
            if isinstance(value, bytes):
                try:
                    value = value.decode('utf-8')
                except UnicodeDecodeError:
                    value = value.decode('utf-8', errors='replace')
            elif value is None:
                value = ''
            else:
                # 确保值是字符串
                value = str(value)

            # 特殊处理User-Agent头
            if key.lower() == 'user-agent':
                # 确保User-Agent是有效的UTF-8字符串
                try:
                    value = value.encode('utf-8', errors='replace').decode('utf-8')
                except Exception:
                    # 如果还有问题，使用安全的替代值
                    value = "Unknown User-Agent"

            processed_headers[key] = value

        return processed_headers

    def _safely_decode_content(self, content):
        """
        安全地解码内容，处理编码错误

        参数:
            content: 可能是二进制数据的内容

        返回:
            解码后的字符串或二进制内容描述
        """
        if not content:
            return ""

        # 检查内容长度
        if len(content) > self.max_content_size:
            try:
                # 尝试解码前部分内容
                decoded = content[:self.max_content_size].decode('utf-8', errors='replace')
                return decoded + "... [内容已截断]"
            except Exception:
                # 如果解码失败，返回二进制描述
                return f"[二进制内容，长度：{len(content)}字节，已截断]"

        # 尝试解码完整内容
        try:
            return content.decode('utf-8', errors='replace')
        except Exception:
            # 如果解码失败，返回二进制描述
            return f"[二进制内容，长度：{len(content)}字节]"

    def _send_to_backend_nonblocking(self, data):
        """以非阻塞方式发送数据到后端"""
        try:
            # 设置代理
            proxies = None
            if self.use_proxy:
                proxies = {
                    "http": self.proxy_url,
                    "https": self.proxy_url
                }

            # 发送请求，设置超时
            response = requests.post(
                self.backend_url,
                json=data,
                timeout=self.timeout,
                proxies=proxies
            )
            ctx.log.info(f"后端响应状态码: {response.status_code}")
        except requests.exceptions.RequestException as e:
            ctx.log.warn(f"发送数据到后端失败: {str(e)}")


# 实例化代理类，使mitmproxy能够加载它
addons = [Proxy()]