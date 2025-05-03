import asyncio
import socket
import binascii
import aiohttp
from urllib.parse import urlparse, urljoin


class NetworkInfoScanner:
    """
    网络信息扫描模块：负责扫描网络相关信息
    """

    def __init__(self):
        """初始化扫描器"""
        # 添加缓存来记录已扫描过的资产和端口组合
        self.port_scan_cache = set()  # 缓存格式：(host, port1,port2,...)
        # 添加记录已发现的开放端口
        self.discovered_ports = {}  # 格式：{host: set(ports)}

    
    
    def safe_decode(self, value):
        """
        安全地解码任何值，处理所有可能的编码错误
        """
        if value is None:
            return ""

        if isinstance(value, bytes):
            try:
                # 首先尝试UTF-8解码
                return value.decode('utf-8', errors='replace')
            except Exception:
                # 尝试其他编码
                for encoding in ['latin1', 'cp1252', 'iso-8859-1', 'gbk']:
                    try:
                        return value.decode(encoding, errors='replace')
                    except:
                        continue

                # 如果所有解码都失败，转为十六进制表示
                try:
                    return f"[二进制数据: {value[:20].hex()}...]"
                except:
                    return "[二进制数据]"

        if isinstance(value, str):
            # 如果已经是字符串，确保它是有效的UTF-8
            try:
                valid_str = value.encode('utf-8', errors='replace').decode('utf-8')
                return valid_str
            except Exception:
                return value.replace('\ufffd', '?')  # 替换替换字符为问号

        # 处理其他类型
        try:
            return str(value)
        except Exception:
            return "[无法转换为字符串的对象]"


    def format_banner_data(self, data):
        """
        格式化Banner数据，处理可能的乱码问题

        参数:
            data: 二进制Banner数据

        返回:
            格式化后的Banner字符串
        """
        if not data:
            return "端口开放，无banner信息"

        # 策略1: 尝试不同的编码方式
        best_decoded = None
        best_printable_ratio = 0

        # 尝试多种编码
        for encoding in ['utf-8', 'ascii', 'latin1', 'gbk', 'gb2312']:
            try:
                # 解码数据
                decoded = data.decode(encoding, errors='replace')

                # 计算可打印字符比例
                printable_count = sum(1 for c in decoded if c.isprintable() and c != '�')
                printable_ratio = printable_count / len(decoded) if decoded else 0

                # 如果这个编码产生了更高比例的可打印字符，使用它
                if printable_ratio > best_printable_ratio:
                    best_printable_ratio = printable_ratio
                    best_decoded = decoded

                    # 如果几乎全是可打印字符，认为这是正确的编码
                    if printable_ratio > 0.95:
                        break
            except Exception:
                continue

        # 如果没有找到合适的编码或可打印字符比例太低
        if not best_decoded or best_printable_ratio < 0.5:
            # 策略2: 尝试提取ASCII部分
            ascii_text = self.extract_ascii_text(data)
            if ascii_text and len(ascii_text) > 10:  # 至少有10个可读字符
                return ascii_text

            # 策略3: 转为十六进制展示
            hex_data = binascii.hexlify(data[:32]).decode('ascii')
            return f"二进制数据 (前32字节: {hex_data})"

        # 清理解码后的文本
        clean_text = self.clean_banner(best_decoded)

        # 如果清理后的文本很短，可能是因为大部分是不可打印字符被移除了
        if len(clean_text) < 5 and len(data) > 20:
            hex_data = binascii.hexlify(data[:32]).decode('ascii')
            return f"二进制数据 (前32字节: {hex_data})"

        return clean_text

    def clean_banner(self, text):
        """清理Banner文本，移除不可打印字符"""
        if not text:
            return ""

        # 将控制字符(除了常见的空白字符)替换为空格
        cleaned = ""
        for c in text:
            if c.isprintable() or c in [' ', '\t', '\n', '\r']:
                cleaned += c
            else:
                cleaned += ' '

        # 将多个连续空格替换为单个空格
        import re
        cleaned = re.sub(r'\s+', ' ', cleaned)

        # 修剪前后空白
        cleaned = cleaned.strip()

        return cleaned

    def extract_ascii_text(self, data):
        """从二进制数据中提取可读的ASCII文本"""
        if not data:
            return ""

        # 提取ASCII可打印字符 (32-126)
        ascii_chars = []
        for b in data:
            if 32 <= b <= 126:  # ASCII可打印字符范围
                ascii_chars.append(chr(b))
            else:
                # 对于不可打印字符，添加空格作为分隔
                # 但避免添加连续的空格
                if not ascii_chars or ascii_chars[-1] != ' ':
                    ascii_chars.append(' ')

        # 转换为字符串并清理多余空格
        result = ''.join(ascii_chars).strip()

        # 将多个连续空格替换为单个空格
        import re
        result = re.sub(r'\s+', ' ', result)

        return result

    def clear_cache(self):
        """清除扫描缓存"""
        self.port_scan_cache.clear()
        self.discovered_ports.clear()
        print("已清除端口扫描缓存")

    def get_cache_size(self):
        """获取当前缓存大小"""
        return len(self.port_scan_cache)