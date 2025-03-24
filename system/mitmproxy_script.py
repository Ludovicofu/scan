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
        self.timeout = 5  # 发送数据到后端的超时时间，单位为秒
        self.use_proxy = False
        self.proxy_url = "http://localhost:7890"
        self.skip_targets = set()  # 要跳过的目标列表

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
            # 如果目标在跳过列表中，则不处理
            host = flow.request.host
            if host in self.skip_targets:
                return

            # 计算响应时间
            response_time = int((time.time() - flow.request.timestamp_start) * 1000)  # 毫秒

            # 准备请求数据
            req_headers = dict(flow.request.headers)
            resp_headers = dict(flow.response.headers)

            # 获取请求内容，可能是二进制数据
            req_content = ""
            if flow.request.content:
                try:
                    req_content = flow.request.content.decode('utf-8')
                except UnicodeDecodeError:
                    req_content = base64.b64encode(flow.request.content).decode('utf-8')

            # 获取响应内容，可能是二进制数据
            resp_content = ""
            if flow.response.content:
                try:
                    resp_content = flow.response.content.decode('utf-8')
                except UnicodeDecodeError:
                    resp_content = base64.b64encode(flow.response.content).decode('utf-8')

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
            self._send_to_backend_nonblocking(data)
        except Exception as e:
            ctx.log.warn(f"处理响应数据时出错: {str(e)}")

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
            ctx.log.info(f"发送数据到后端: {data['url']}, 状态码: {data['status_code']}")
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