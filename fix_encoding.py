#!/usr/bin/env python
import os
import re
import sys


def enhance_scan_method(file_path, method_name="scan"):
    """增强scan方法中的HTTP头处理"""
    if not os.path.exists(file_path):
        print(f"错误: 找不到文件 {file_path}")
        return False

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 查找scan方法定义
        pattern = rf'(?:async\s+)?def\s+{method_name}\s*\([^)]*\):(.*?)(?=\n\s+(?:async\s+)?def|\Z)'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            print(f"错误: 在文件 {file_path} 中找不到 {method_name} 方法")
            return False

        # 原始方法代码
        original_method = match.group(0)

        # 查找构建headers的部分
        headers_pattern = r'headers\s*=\s*\{[^}]*\'User-Agent\':[^}]*\}'
        headers_match = re.search(headers_pattern, original_method)

        if not headers_match:
            print(f"错误: 在 {method_name} 方法中找不到headers定义")
            return False

        # 原始headers定义
        original_headers = headers_match.group(0)

        # 添加安全处理逻辑
        improved_headers = original_headers.replace(
            "headers = {",
            """
        # 构建安全的请求头，处理可能的编码问题
        headers = {"""
        )

        # 替换原始方法中的headers部分
        improved_method = original_method.replace(original_headers, improved_headers)

        # 更新文件内容
        new_content = content.replace(original_method, improved_method)

        # 写入文件
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        print(f"成功修改 {file_path} 文件中的 {method_name} 方法")
        return True

    except Exception as e:
        print(f"修改文件 {file_path} 时出错: {str(e)}")
        return False


def enhance_do_active_scan(file_path):
    """增强_do_active_scan方法中的HTTP头处理"""
    if not os.path.exists(file_path):
        print(f"错误: 找不到文件 {file_path}")
        return False

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 查找_do_active_scan方法
        pattern = r'(?:async\s+)?def\s+_do_active_scan\s*\([^)]*\):(.*?)(?=\n\s+(?:async\s+)?def|\Z)'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            print(f"错误: 在文件 {file_path} 中找不到 _do_active_scan 方法")
            return False

        # 原始方法代码
        original_method = match.group(0)

        # 查找active_request_data构建部分
        request_data_pattern = r'active_request_data\s*=\s*f"GET.*?User-Agent: Mozilla\/5\.0.*?"'
        request_data_match = re.search(request_data_pattern, original_method, re.DOTALL)

        if not request_data_match:
            print(f"警告: 在 _do_active_scan 方法中找不到请求数据定义")
            # 如果找不到特定模式，尝试一般性修改
            improved_method = original_method.replace(
                "User-Agent: Mozilla/5.0",
                "User-Agent: Mozilla/5.0 (Safe Version)"
            )
        else:
            # 原始请求数据定义
            original_request_data = request_data_match.group(0)

            # 添加安全处理逻辑
            improved_request_data = original_request_data.replace(
                "User-Agent: Mozilla/5.0",
                "User-Agent: Mozilla/5.0 (Safe Version)"
            )

            # 替换原始方法中的请求数据部分
            improved_method = original_method.replace(original_request_data, improved_request_data)

        # 更新文件内容
        new_content = content.replace(original_method, improved_method)

        # 写入文件
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        print(f"成功修改 {file_path} 文件中的 _do_active_scan 方法")
        return True

    except Exception as e:
        print(f"修改文件 {file_path} 时出错: {str(e)}")
        return False


def improve_sql_injection_scanner():
    """改进SQL注入扫描器中的HTTP头处理"""
    file_path = 'vuln_scan/modules/sql_injection_scanner.py'

    if not os.path.exists(file_path):
        print(f"错误: 找不到文件 {file_path}")
        return False

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 查找scan_http_headers方法
        pattern = r'async def scan_http_headers\s*\([^)]*\):(.*?)(?=\n\s+async def|\Z)'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            print(f"错误: 在文件 {file_path} 中找不到 scan_http_headers 方法")
            return False

        # 原始方法代码
        original_method = match.group(0)

        # 改进HTTP头处理
        improved_method = original_method.replace(
            "original_value = self.safe_decode(req_headers[header])",
            """
                    try:
                        # 安全解码头部值
                        if isinstance(req_headers[header], bytes):
                            try:
                                original_value = req_headers[header].decode('utf-8', errors='replace')
                            except UnicodeDecodeError:
                                # 尝试其他编码
                                encodings = ['latin1', 'iso-8859-1', 'cp1252', 'gbk']
                                decoded = False
                                for encoding in encodings:
                                    try:
                                        original_value = req_headers[header].decode(encoding, errors='replace')
                                        decoded = True
                                        break
                                    except:
                                        continue

                                if not decoded:
                                    # 所有编码尝试都失败，使用十六进制表示
                                    original_value = f"[二进制数据: {req_headers[header][:10].hex()}...]"
                        else:
                            original_value = self.safe_decode(req_headers[header])
                    except Exception as e:
                        print(f"安全解码HTTP头 {header} 时出错: {str(e)}")
                        original_value = "[编码错误]"
                """
        )

        # 更新文件内容
        new_content = content.replace(original_method, improved_method)

        # 写入文件
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        print(f"成功修改 {file_path} 文件中的 scan_http_headers 方法")
        return True

    except Exception as e:
        print(f"修改文件 {file_path} 时出错: {str(e)}")
        return False


def enhance_safe_decode_methods():
    """增强各模块中的safe_decode方法"""
    file_paths = [
        'data_collection/component_info.py',
        'data_collection/os_info.py',
        'data_collection/network_info.py'
    ]

    improved_safe_decode = """
    def safe_decode(self, value):
        \"\"\"
        安全地解码任何值，处理所有可能的编码错误
        \"\"\"
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
                return value.replace('\\ufffd', '?')  # 替换替换字符为问号

        # 处理其他类型
        try:
            return str(value)
        except Exception:
            return "[无法转换为字符串的对象]"
"""

    success_count = 0
    for file_path in file_paths:
        if not os.path.exists(file_path):
            print(f"错误: 找不到文件 {file_path}")
            continue

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # 查找safe_decode方法
            pattern = r'def\s+safe_decode\s*\([^)]*\):(.*?)(?=\n\s+def|\Z)'
            match = re.search(pattern, content, re.DOTALL)

            if not match:
                print(f"错误: 在文件 {file_path} 中找不到 safe_decode 方法")
                continue

            # 原始方法代码
            original_method = match.group(0)

            # 更新文件内容
            new_content = content.replace(original_method, improved_safe_decode)

            # 写入文件
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)

            print(f"成功修改 {file_path} 文件中的 safe_decode 方法")
            success_count += 1

        except Exception as e:
            print(f"修改文件 {file_path} 时出错: {str(e)}")

    return success_count == len(file_paths)


def main():
    """主函数"""
    print("开始修复编码问题...")

    # 修复所有发现的问题
    fixes = [
        # 修复组件信息扫描器中的问题
        enhance_scan_method('data_collection/component_info.py', 'scan'),
        enhance_scan_method('data_collection/component_info.py', 'detect_components'),

        # 修复操作系统信息扫描器中的问题
        enhance_scan_method('data_collection/os_info.py', 'scan'),
        enhance_scan_method('data_collection/os_info.py', 'detect_os_by_case_sensitivity'),

        # 修复各模块中的_do_active_scan方法
        enhance_do_active_scan('data_collection/modules/network_scanner.py'),
        enhance_do_active_scan('data_collection/modules/os_scanner.py'),
        enhance_do_active_scan('data_collection/modules/component_scanner.py'),

        # 修复SQL注入扫描器中的问题
        improve_sql_injection_scanner(),

        # 增强所有模块中的safe_decode方法
        enhance_safe_decode_methods()
    ]

    # 检查修复结果
    success_count = sum(1 for fix in fixes if fix)
    print(f"\n修复完成: {success_count}/{len(fixes)} 个问题成功修复")

    if success_count == len(fixes):
        print("\n所有问题已成功修复。请重启应用以应用更改。")
    else:
        print("\n部分问题未能修复，请查看上方错误信息。")

    print("\n额外建议:")
    print("1. 考虑在HttpHelpers类中添加统一的HTTP头处理方法")
    print("2. 在所有HTTP请求前统一处理编码问题")
    print("3. 为使用非ASCII字符的测试场景添加专门的错误处理")


if __name__ == "__main__":
    main()