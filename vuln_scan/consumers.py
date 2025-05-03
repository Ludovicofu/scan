# vuln_scan/consumers.py

import json
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .scanner import VulnScanner
from .models import VulnScanResult
from data_collection.models import Asset, SystemSettings, SkipTarget
from django.utils import timezone
import re


class VulnScanConsumer(AsyncWebsocketConsumer):
    """
    WebSocket消费者：处理漏洞扫描模块的WebSocket连接
    """
    # 类级别的SQL错误模式，用于在前端显示特定的SQL错误
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysqli",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that (corresponds to|fits) your MySQL server version",
        r"MySqlClient\\.",
        r"com\\.mysql\\.jdbc\\.exceptions",
        r"ORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"SQLSTATE\\[",
        r"SQL Server message",
        r"Warning.*mssql_",
        r"Driver.*? SQL[\\-\\_\\ ]*Server",
        r"JET Database Engine",
        r"Microsoft Access Driver",
        r"Syntax error \\(missing operator\\) in query expression"
    ]

    async def connect(self):
        """处理WebSocket连接"""
        # 将客户端添加到vuln_scan_scanner组
        await self.channel_layer.group_add(
            'vuln_scan_scanner',
            self.channel_name
        )

        # 将客户端添加到settings_update组
        await self.channel_layer.group_add(
            'settings_update',
            self.channel_name
        )

        # 接受WebSocket连接
        await self.accept()

        # 初始化扫描器
        self.scanner = VulnScanner()

        # 发送当前系统设置
        settings = await self.get_system_settings()
        await self.send(text_data=json.dumps({
            'type': 'settings',
            'data': settings
        }))

        # 发送当前跳过目标列表
        skip_targets = await self.get_skip_targets()
        await self.send(text_data=json.dumps({
            'type': 'skip_targets',
            'data': skip_targets
        }))

    async def disconnect(self, close_code):
        """处理WebSocket断开连接"""
        # 将客户端从vuln_scan_scanner组移除
        await self.channel_layer.group_discard(
            'vuln_scan_scanner',
            self.channel_name
        )

        # 将客户端从settings_update组移除
        await self.channel_layer.group_discard(
            'settings_update',
            self.channel_name
        )

    async def receive(self, text_data):
        """处理从WebSocket接收到的消息"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')

            if message_type == 'start_scan':
                # 开始扫描
                scan_options = data.get('options', {})
                await self.start_scan(scan_options)

            elif message_type == 'stop_scan':
                # 停止扫描
                await self.stop_scan()

            elif message_type == 'get_scan_results':
                # 获取扫描结果
                filters = data.get('filters', {})
                results = await self.get_scan_results(filters)
                await self.send(text_data=json.dumps({
                    'type': 'scan_results',
                    'data': results
                }))

            elif message_type == 'reset_cache':
                # 重置缓存以确保不会遗漏结果
                self.scanner.reset_scan_state()
                await self.send(text_data=json.dumps({
                    'type': 'cache_reset',
                    'message': '缓存已重置'
                }))

        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': '无效的JSON数据'
            }))
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': str(e)
            }))

    async def proxy_data(self, event):
        """处理从代理接收到的HTTP数据"""
        # 获取HTTP数据
        data = event['data']

        # 处理数据（扫描）
        await self.process_proxy_data(data)

    async def settings_update(self, event):
        """处理系统设置更新事件"""
        # 获取新设置
        settings_data = event['data']

        # 更新扫描器设置
        await self.update_scanner_settings(settings_data)

        # 发送设置更新通知给客户端
        await self.send(text_data=json.dumps({
            'type': 'settings_update',
            'data': settings_data
        }))

    async def skip_target_update(self, event):
        """处理跳过目标更新事件"""
        # 获取操作类型和目标
        action = event['action']
        target = event['target']

        # 更新扫描器跳过目标
        if action == 'add':
            await self.add_scanner_skip_target(target)
        elif action == 'remove':
            await self.remove_scanner_skip_target(target)

        # 发送跳过目标更新通知给客户端
        await self.send(text_data=json.dumps({
            'type': 'skip_target_update',
            'action': action,
            'target': target
        }))

    async def scan_progress(self, event):
        """处理扫描进度更新事件"""
        # 发送扫描进度更新通知给客户端
        await self.send(text_data=json.dumps({
            'type': 'scan_progress',
            'data': event['data']
        }))

    async def scan_result(self, event):
        """处理扫描结果事件，增强错误回显型SQL注入的显示"""
        # 复制结果数据以避免修改原始数据
        result_data = dict(event['data'])

        # 对SQL注入漏洞结果进行处理
        if result_data.get('vuln_type') == 'sql_injection':
            # 特别处理错误回显型SQL注入
            if result_data.get('vuln_subtype') == 'error_based':
                # 从proof中提取SQL错误信息
                proof = result_data.get('proof', '')
                error_match = self.extract_sql_error_from_proof(proof)

                # 如果成功提取到错误匹配，添加到结果中
                if error_match:
                    result_data['matched_error'] = error_match

                # 如果没有从proof中提取到错误，尝试从response中查找
                elif result_data.get('response'):
                    response = result_data['response']
                    error_match = self.extract_sql_error_from_response(response)
                    if error_match:
                        result_data['matched_error'] = error_match

            # 确保响应和请求数据完整性
            if 'request' in result_data and result_data['request']:
                # 确保请求不会太长
                if len(result_data['request']) > 2000:
                    result_data['request'] = result_data['request'][:2000] + "...[已截断]"

            if 'response' in result_data and result_data['response']:
                # 确保响应不会太长
                if len(result_data['response']) > 2000:
                    result_data['response'] = result_data['response'][:2000] + "...[已截断]"

        # 发送处理后的结果
        await self.send(text_data=json.dumps({
            'type': 'scan_result',
            'data': result_data
        }))

    def extract_sql_error_from_proof(self, proof):
        """从proof中提取SQL错误信息"""
        if not proof:
            return None

        # 尝试不同的提取模式
        # 1. 尝试提取"包含SQL错误信息: xxx"格式
        match = re.search(r'包含SQL错误信息[：:]\s*(.+?)(?:[，。,\.;\s]|$)', proof)
        if match and match.group(1):
            return match.group(1).strip()

        # 2. 尝试提取"SQL错误信息: xxx"格式
        match = re.search(r'SQL错误信息[：:]\s*(.+?)(?:[，。,\.;\s]|$)', proof)
        if match and match.group(1):
            return match.group(1).strip()

        # 如果没有找到明确模式，检查是否包含任何已知SQL错误关键词
        for pattern in self.SQL_ERROR_PATTERNS:
            # 移除正则表达式元字符
            clean_pattern = pattern.replace('\\', '').replace('.*', ' ').replace('[', '').replace(']', '')
            if clean_pattern in proof:
                return clean_pattern

        return None

    def extract_sql_error_from_response(self, response):
        """从响应中提取SQL错误信息"""
        if not response:
            return None

        # 检查响应中是否包含已知SQL错误关键词
        for pattern in self.SQL_ERROR_PATTERNS:
            try:
                compiled_pattern = re.compile(pattern, re.IGNORECASE)
                match = compiled_pattern.search(response)
                if match:
                    return match.group(0)
            except Exception:
                # 如果正则编译失败，尝试简化模式
                clean_pattern = pattern.replace('\\', '').replace('.*', ' ').replace('[', '').replace(']', '')
                if clean_pattern in response:
                    return clean_pattern

        return None