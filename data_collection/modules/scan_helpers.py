"""
扫描辅助模块：提供各种扫描辅助方法
"""
from asgiref.sync import sync_to_async
from django.utils import timezone
from ..models import Asset, ScanResult
from rules.models import InfoCollectionRule


class ScanHelpers:
    """扫描辅助类：提供各种扫描辅助方法"""

    def get_status_text(self, status_code):
        """获取HTTP状态码对应的文本描述"""
        status_dict = {
            200: "OK",
            201: "Created",
            202: "Accepted",
            204: "No Content",
            301: "Moved Permanently",
            302: "Found",
            303: "See Other",
            304: "Not Modified",
            307: "Temporary Redirect",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            408: "Request Timeout",
            500: "Internal Server Error",
            501: "Not Implemented",
            502: "Bad Gateway",
            503: "Service Unavailable",
            504: "Gateway Timeout",
        }
        return status_dict.get(status_code, "Unknown")

    def format_request_data(self, method, url, headers, content):
        """格式化请求数据"""
        request_data = f"{method} {url}\n"

        # 预处理并过滤无效的头部
        filtered_headers = {}
        for header, value in headers.items():
            # 确保键和值都是字符串
            if isinstance(header, bytes):
                try:
                    header = header.decode('utf-8', errors='replace')
                except Exception:
                    # 解码失败，跳过此头部
                    continue
            elif not isinstance(header, str):
                try:
                    header = str(header)
                except Exception:
                    # 转换失败，跳过此头部
                    continue

            # 处理值
            if isinstance(value, bytes):
                try:
                    value = value.decode('utf-8', errors='replace')
                except Exception:
                    # 解码失败，使用占位符
                    value = "[二进制数据]"
            elif not isinstance(value, str):
                try:
                    value = str(value)
                except Exception:
                    # 转换失败，使用占位符
                    value = "[无法转换为字符串]"

            filtered_headers[header] = value

        # 添加过滤后的头部
        for header, value in filtered_headers.items():
            request_data += f"{header}: {value}\n"

        # 处理请求内容
        if content:
            if isinstance(content, bytes):
                try:
                    content = content.decode('utf-8', errors='replace')
                except Exception:
                    # 解码失败，使用占位符
                    content = "[二进制请求内容，无法显示]"
            elif not isinstance(content, str):
                try:
                    content = str(content)
                except Exception:
                    content = "[无法转换为字符串的请求内容]"

        request_data += f"\n{content}"
        return request_data

    def format_response_data(self, status_code, headers, content):
        """格式化响应数据"""
        response_data = f"HTTP/1.1 {status_code} {self.get_status_text(status_code)}\n"

        # 预处理并过滤无效的头部
        filtered_headers = {}
        for header, value in headers.items():
            # 确保键和值都是字符串
            if isinstance(header, bytes):
                try:
                    header = header.decode('utf-8', errors='replace')
                except Exception:
                    # 解码失败，跳过此头部
                    continue
            elif not isinstance(header, str):
                try:
                    header = str(header)
                except Exception:
                    # 转换失败，跳过此头部
                    continue

            # 处理值
            if isinstance(value, bytes):
                try:
                    value = value.decode('utf-8', errors='replace')
                except Exception:
                    # 解码失败，使用占位符
                    value = "[二进制数据]"
            elif not isinstance(value, str):
                try:
                    value = str(value)
                except Exception:
                    # 转换失败，使用占位符
                    value = "[无法转换为字符串]"

            filtered_headers[header] = value

        # 添加过滤后的头部
        for header, value in filtered_headers.items():
            response_data += f"{header}: {value}\n"

        # 处理响应内容
        if content:
            if isinstance(content, bytes):
                try:
                    content = content.decode('utf-8', errors='replace')
                except Exception:
                    # 解码失败，使用占位符
                    content = "[二进制响应内容，无法显示]"
            elif not isinstance(content, str):
                try:
                    content = str(content)
                except Exception:
                    content = "[无法转换为字符串的响应内容]"

        response_data += f"\n{content}"
        return response_data

    @sync_to_async
    def get_asset(self, asset_id):
        """获取资产"""
        try:
            return Asset.objects.get(id=asset_id)
        except Asset.DoesNotExist:
            print(f"资产不存在，ID: {asset_id}")
            return None
        except Exception as e:
            print(f"获取资产失败: {str(e)}")
            return None

    @sync_to_async
    def check_existing_result(self, asset, module, description, rule_type, match_value):
        """检查是否已存在相同的扫描结果"""
        try:
            return ScanResult.objects.filter(
                asset=asset,
                module=module,
                description=description,
                rule_type=rule_type,
                match_value=match_value
            ).exists()
        except Exception as e:
            print(f"检查现有结果失败: {str(e)}")
            return False  # 出错时返回False，允许创建新结果

    @sync_to_async
    def get_rules(self, module, scan_type):
        """获取规则"""
        try:
            rules = InfoCollectionRule.objects.filter(
                module=module,
                scan_type=scan_type,
                is_enabled=True
            )

            result = []
            for rule in rules:
                # 解析匹配值（按行分割）
                match_values = [v.strip() for v in rule.match_values.splitlines() if v.strip()]

                # 解析行为（按行分割）
                behaviors = []
                if rule.behaviors:
                    behaviors = [b.strip() for b in rule.behaviors.splitlines() if b.strip()]

                result.append({
                    'id': rule.id,
                    'description': rule.description,
                    'rule_type': rule.rule_type,
                    'match_values': match_values,
                    'behaviors': behaviors
                })

            return result
        except Exception as e:
            print(f"获取规则失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return []  # 出错时返回空列表

    @sync_to_async
    def save_scan_result(self, asset, module, scan_type, description, rule_type, match_value, behavior, request_data,
                         response_data):
        """保存扫描结果"""
        try:
            # 创建扫描结果，同时保存请求和响应数据
            scan_result = ScanResult.objects.create(
                asset=asset,
                module=module,
                scan_type=scan_type,
                description=description,
                rule_type=rule_type,
                match_value=match_value,
                behavior=behavior,
                request_data=request_data,
                response_data=response_data,
                scan_date=timezone.now()
            )
            return scan_result
        except Exception as e:
            # 如果保存失败（例如唯一约束冲突），则忽略错误
            print(f"保存扫描结果失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return None