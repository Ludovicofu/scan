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

        # 内容大小限制，降低到30KB (原来是50000)
        self.max_content_size = 30000

        # 请求头和响应头最大大小
        self.max_header_size = 8000

        # 需要跳过的内容类型
        self.skip_content_types = [
            'image/',  # 所有图片类型
            'video/',  # 所有视频类型
            'audio/',  # 所有音频类型
            'font/',  # 字体文件
            'application/pdf',
            'application/zip',
            'application/x-rar-compressed',
            'application/x-7z-compressed',
            'application/octet-stream',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml',
            'application/x-shockwave-flash',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml',
        ]

        # 跳过的文件扩展名
        self.skip_extensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp',
            '.mp4', '.webm', '.mov', '.avi', '.wmv', '.flv', '.mkv',
            '.mp3', '.wav', '.ogg', '.aac', '.flac',
            '.pdf', '.zip', '.rar', '.7z', '.tar', '.gz', '.exe', '.dll',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.swf', '.iso', '.bin'
        ]

        # 统计信息
        self.processed_flows = 0
        self.skipped_flows = 0
        self.large_content_flows = 0
        self.start_time = time.time()

    def load(self, loader):
        """初始化加载"""
        ctx.log.info("被动代理漏洞扫描系统代理已启动！监听端口：7891")
        ctx.log.info(f"内容大小限制: {self.max_content_size} 字节")
        ctx.log.info(f"跳过的内容类型: {', '.join(self.skip_content_types)}")

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

            # 更新处理统计
            self.processed_flows += 1

            # 检查文件扩展名
            url_path = flow.request.path.lower()
            for ext in self.skip_extensions:
                if url_path.endswith(ext):
                    ctx.log.info(f"跳过文件扩展名 {ext}: {flow.request.url}")
                    self.skipped_flows += 1
                    return

            # 检查内容类型
            content_type = flow.response.headers.get('Content-Type', '')
            for skip_type in self.skip_content_types:
                if skip_type in content_type.lower():
                    ctx.log.info(f"跳过内容类型 {content_type}: {flow.request.url}")
                    self.skipped_flows += 1
                    return

            # 检查响应内容大小
            resp_size = len(flow.response.content) if flow.response.content else 0
            if resp_size > self.max_content_size * 5:  # 如果响应大小超过限制的5倍，直接跳过
                ctx.log.info(f"跳过大型响应 ({resp_size} 字节): {flow.request.url}")
                self.skipped_flows += 1
                self.large_content_flows += 1
                return

            # 检查请求内容大小
            req_size = len(flow.request.content) if flow.request.content else 0
            if req_size > self.max_content_size * 5:  # 如果请求大小超过限制的5倍，直接跳过
                ctx.log.info(f"跳过大型请求 ({req_size} 字节): {flow.request.url}")
                self.skipped_flows += 1
                self.large_content_flows += 1
                return

            # 计算响应时间
            response_time = int((time.time() - flow.request.timestamp_start) * 1000)  # 毫秒

            # 安全地处理请求头，确保编码正确
            req_headers = self._safely_process_headers(flow.request.headers)
            resp_headers = self._safely_process_headers(flow.response.headers)

            # 获取请求内容，可能是二进制数据
            req_content = self._safely_decode_content(flow.request.content, is_request=True)

            # 获取响应内容，可能是二进制数据
            resp_content = self._safely_decode_content(flow.response.content, is_request=False)

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

            # 每100个请求输出一次统计信息
            if self.processed_flows % 100 == 0:
                self._print_stats()

        except Exception as e:
            ctx.log.warn(f"处理响应数据时出错: {str(e)}")
            import traceback
            traceback.print_exc()

    def _safely_process_headers(self, headers):
        """
        安全地处理HTTP头，确保所有值都是有效的UTF-8字符串
        并限制头部大小

        参数:
            headers: HTTP头字典

        返回:
            处理后的HTTP头字典
        """
        processed_headers = {}
        total_size = 0

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
                    value = value.decode('utf-8', errors='replace')
                except Exception:
                    # 如果仍然出错，使用占位符
                    value = "[二进制数据]"
            elif value is None:
                value = ''
            else:
                # 确保值是字符串
                try:
                    value = str(value)
                except Exception:
                    value = "[无法转换为字符串]"

            # 计算当前键值对的大小
            pair_size = len(key) + len(value)

            # 检查总大小是否超过限制
            if total_size + pair_size > self.max_header_size:
                # 如果添加这个键值对会超出限制，则截断值
                if len(key) < 50:  # 只有键不太长的情况下才保留
                    truncated_size = self.max_header_size - total_size - len(key) - 20  # 预留20个字符给截断提示
                    if truncated_size > 10:  # 如果可以至少保留10个字符
                        value = value[:truncated_size] + "... [已截断]"
                        pair_size = len(key) + len(value)
                        processed_headers[key] = value
                        total_size += pair_size
                continue  # 跳过这个头部

            processed_headers[key] = value
            total_size += pair_size

            # 如果已经达到或超过了总大小限制，停止处理更多头部
            if total_size >= self.max_header_size:
                processed_headers[
                    "WARNING"] = f"头部已达到大小限制 ({self.max_header_size} 字节)，一些头部可能已被截断或跳过"
                break

        return processed_headers

    def _safely_decode_content(self, content, is_request=False):
        """
        安全地解码内容，处理编码错误
        并限制内容大小

        参数:
            content: 可能是二进制数据的内容
            is_request: 是否是请求内容（请求内容的大小限制可能更严格）

        返回:
            解码后的字符串或二进制内容描述
        """
        if not content:
            return ""

        # 设置内容大小限制（请求内容和响应内容可能有不同的限制）
        size_limit = self.max_content_size // 2 if is_request else self.max_content_size
        content_size = len(content)

        # 检查内容是否为二进制数据（是否包含很多非可打印字符）
        printable_ratio = self._calc_printable_ratio(content)
        is_likely_binary = printable_ratio < 0.7  # 如果可打印字符比例低于70%，可能是二进制数据

        # 跟踪大内容
        if content_size > size_limit:
            self.large_content_flows += 1

        # 检查内容长度
        if content_size > size_limit:
            # 如果是二进制数据或非文本内容，只返回大小信息
            if is_likely_binary:
                return f"[二进制内容，大小：{content_size} 字节，已截断]"

            # 尝试解码前部分内容
            try:
                # 截取更小的一部分，以提高性能
                preview_size = min(2000, size_limit // 2)  # 最大预览2KB
                decoded_preview = content[:preview_size].decode('utf-8', errors='replace')
                return decoded_preview + f"\n... [内容已截断，原始大小：{content_size} 字节]"
            except Exception:
                # 如果解码失败，返回二进制描述
                return f"[二进制内容，长度：{content_size} 字节，已截断]"

        # 尝试解码完整内容
        try:
            # 如果明显是二进制数据且不太大，返回二进制内容描述
            if is_likely_binary and content_size > 1000:
                return f"[二进制内容，长度：{content_size} 字节]"

            # 尝试解码为文本
            return content.decode('utf-8', errors='replace')
        except Exception:
            # 如果解码失败，返回二进制描述
            return f"[二进制内容，长度：{len(content)}字节]"

    def _calc_printable_ratio(self, data):
        """计算数据中可打印字符的比例"""
        if not data or len(data) == 0:
            return 0

        # 取样以提高效率
        sample_size = min(1000, len(data))
        sample = data[:sample_size]

        # 计算可打印字符的数量
        printable_count = 0
        for byte in sample:
            # ASCII 32-126 是可打印字符，9是制表符，10是换行符，13是回车符
            if byte in (9, 10, 13) or (32 <= byte <= 126):
                printable_count += 1

        return printable_count / sample_size

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

    def _print_stats(self):
        """打印统计信息"""
        runtime = time.time() - self.start_time
        ctx.log.info("-" * 50)
        ctx.log.info(f"代理运行统计信息:")
        ctx.log.info(f"已处理请求数: {self.processed_flows}")
        ctx.log.info(
            f"已跳过请求数: {self.skipped_flows} ({self.skipped_flows / max(1, self.processed_flows) * 100:.1f}%)")
        ctx.log.info(
            f"大内容请求数: {self.large_content_flows} ({self.large_content_flows / max(1, self.processed_flows) * 100:.1f}%)")
        ctx.log.info(f"运行时间: {runtime:.1f} 秒")
        ctx.log.info(f"处理速率: {self.processed_flows / max(1, runtime):.1f} 请求/秒")
        ctx.log.info("-" * 50)


# 实例化代理类，使mitmproxy能够加载它
addons = [Proxy()]