#!/usr/bin/env python
# -*- coding: utf-8 -*-
# scan_progress_debugger.py - 扫描进度更新逻辑调试脚本

import os
import sys
import logging
import asyncio
import json
import websockets
import traceback
import requests
from urllib.parse import urlparse
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scan_debug.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 配置参数
DJANGO_BASE_URL = "http://localhost:8000"  # Django服务地址
WS_BASE_URL = "ws://localhost:8000"  # WebSocket服务地址
DATA_COLLECTION_WS = f"{WS_BASE_URL}/ws/data_collection/"
VULN_SCAN_WS = f"{WS_BASE_URL}/ws/vuln_scan/"
PROXY_ENDPOINT = f"{DJANGO_BASE_URL}/proxy/"

# 测试URL (用于模拟被扫描的流量)
TEST_URL = "http://example.com"


class ScanProgressDebugger:
    """扫描进度调试器"""

    def __init__(self):
        self.data_collection_ws = None
        self.vuln_scan_ws = None
        self.progress_events = []
        self.message_log = []

    async def connect_websockets(self):
        """连接到WebSocket服务"""
        logger.info("开始连接WebSocket服务...")

        try:
            self.data_collection_ws = await websockets.connect(DATA_COLLECTION_WS)
            logger.info("成功连接到数据收集WebSocket服务")
        except Exception as e:
            logger.error(f"连接数据收集WebSocket服务失败: {str(e)}")
            return False

        try:
            self.vuln_scan_ws = await websockets.connect(VULN_SCAN_WS)
            logger.info("成功连接到漏洞扫描WebSocket服务")
        except Exception as e:
            logger.error(f"连接漏洞扫描WebSocket服务失败: {str(e)}")
            await self.data_collection_ws.close()
            return False

        return True

    async def listen_for_progress_events(self, ws, name, timeout=30):
        """监听进度事件"""
        logger.info(f"开始监听 {name} 的进度事件...")
        try:
            while True:
                try:
                    message = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    logger.info(f"接收到 {name} 消息: {message[:200]}...")

                    # 解析消息
                    data = json.loads(message)
                    self.message_log.append({
                        'timestamp': datetime.now().isoformat(),
                        'source': name,
                        'data': data
                    })

                    # 检查是否为进度事件
                    if data.get('type') == 'scan_progress':
                        logger.info(f"检测到进度事件: {json.dumps(data, ensure_ascii=False)}")
                        self.progress_events.append({
                            'timestamp': datetime.now().isoformat(),
                            'source': name,
                            'data': data
                        })
                except asyncio.TimeoutError:
                    logger.warning(f"{name} 监听超时")
                    break
                except Exception as e:
                    logger.error(f"{name} 监听出错: {str(e)}")
                    traceback.print_exc()
                    break
        except Exception as e:
            logger.error(f"{name} 监听任务异常: {str(e)}")
            traceback.print_exc()

    def send_test_http_request(self):
        """发送测试HTTP请求模拟代理数据"""
        logger.info(f"发送测试HTTP请求到 {TEST_URL}...")

        try:
            # 获取测试页面
            response = requests.get(TEST_URL, timeout=10)
            logger.info(f"成功获取测试页面，状态码: {response.status_code}")

            # 构建模拟代理数据
            proxy_data = {
                "url": TEST_URL,
                "method": "GET",
                "req_headers": dict(response.request.headers),
                "req_content": "",
                "status_code": response.status_code,
                "resp_headers": dict(response.headers),
                "resp_content": response.text[:500],  # 截取部分内容
                "response_time": 200  # 模拟响应时间(毫秒)
            }

            # 发送到proxy端点
            proxy_response = requests.post(
                PROXY_ENDPOINT,
                json=proxy_data,
                headers={"Content-Type": "application/json"}
            )

            if proxy_response.status_code == 200:
                logger.info(f"成功发送代理数据，响应: {proxy_response.text}")
                return True
            else:
                logger.error(f"发送代理数据失败，状态码: {proxy_response.status_code}，响应: {proxy_response.text}")
                return False

        except Exception as e:
            logger.error(f"发送测试HTTP请求失败: {str(e)}")
            traceback.print_exc()
            return False

    async def send_start_scan_command(self):
        """发送开始扫描命令"""
        logger.info("发送开始扫描命令...")

        # 发送数据收集扫描命令
        start_command = {
            "type": "start_scan",
            "options": {}
        }

        try:
            await self.data_collection_ws.send(json.dumps(start_command))
            logger.info("成功发送数据收集开始扫描命令")
        except Exception as e:
            logger.error(f"发送数据收集开始扫描命令失败: {str(e)}")
            return False

        try:
            await self.vuln_scan_ws.send(json.dumps(start_command))
            logger.info("成功发送漏洞扫描开始扫描命令")
        except Exception as e:
            logger.error(f"发送漏洞扫描开始扫描命令失败: {str(e)}")
            return False

        return True

    def check_progress_calculation(self):
        """检查进度计算逻辑"""
        logger.info("检查进度计算逻辑...")

        # 检查是否收到进度事件
        if not self.progress_events:
            logger.error("没有收到任何进度事件，扫描器可能没有发送进度更新")
            return False

        # 分析进度事件
        progress_values = [event['data']['data'].get('progress', 0) for event in self.progress_events]
        logger.info(f"进度值序列: {progress_values}")

        # 检查进度值是否有变化
        if len(set(progress_values)) <= 1 and 0 in progress_values:
            logger.error("进度值没有变化，始终为0")
            return False

        return True

    def analyze_websocket_messages(self):
        """分析WebSocket消息"""
        logger.info("分析WebSocket消息...")

        # 检查消息类型分布
        message_types = {}
        for msg in self.message_log:
            msg_type = msg['data'].get('type', 'unknown')
            message_types[msg_type] = message_types.get(msg_type, 0) + 1

        logger.info(f"消息类型分布: {message_types}")

        # 检查scan_progress消息
        progress_messages = [msg for msg in self.message_log if msg['data'].get('type') == 'scan_progress']
        if not progress_messages:
            logger.error("没有scan_progress类型的消息")
            return {
                'issue': 'no_progress_messages',
                'message': '没有接收到任何进度更新消息'
            }

        # 检查进度值
        for i, msg in enumerate(progress_messages):
            progress = msg['data']['data'].get('progress', 0)
            status = msg['data']['data'].get('status', 'unknown')
            logger.info(f"进度消息 {i + 1}: 状态={status}, 进度={progress}")

            if status == 'scanning' and progress == 0:
                return {
                    'issue': 'progress_always_zero',
                    'message': '扫描状态为scanning但进度值始终为0'
                }

        return {'issue': None, 'message': '没有发现明显问题'}

    def generate_report(self):
        """生成调试报告"""
        logger.info("生成调试报告...")

        report = {
            'timestamp': datetime.now().isoformat(),
            'connections': {
                'data_collection_ws': self.data_collection_ws is not None,
                'vuln_scan_ws': self.vuln_scan_ws is not None
            },
            'messages': {
                'total_count': len(self.message_log),
                'progress_events_count': len(self.progress_events)
            },
            'progress_analysis': self.analyze_websocket_messages(),
            'message_log': self.message_log,
            'progress_events': self.progress_events
        }

        # 保存报告到文件
        with open('scan_debug_report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        logger.info("调试报告已保存到 scan_debug_report.json")

        # 打印关键发现
        logger.info("\n==== 调试报告摘要 ====")
        logger.info(
            f"WebSocket连接状态: 数据收集={report['connections']['data_collection_ws']}, 漏洞扫描={report['connections']['vuln_scan_ws']}")
        logger.info(f"总消息数: {report['messages']['total_count']}")
        logger.info(f"进度事件数: {report['messages']['progress_events_count']}")

        if report['progress_analysis']['issue']:
            logger.info(f"发现问题: {report['progress_analysis']['message']}")
        else:
            logger.info("未发现明显WebSocket通信问题")

        return report

    def check_scanner_code(self):
        """检查扫描器代码"""
        logger.info("检查扫描器代码路径...")

        # 检查文件是否存在
        files_to_check = [
            "data_collection/scanner.py",
            "data_collection/consumers.py",
            "vuln_scan/scanner.py",
            "vuln_scan/consumers.py"
        ]

        for file_path in files_to_check:
            if os.path.exists(file_path):
                logger.info(f"文件存在: {file_path}")

                # 读取文件内容
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # 检查关键代码片段
                if "scan_progress" in content:
                    line_num = 1
                    for line in content.split('\n'):
                        if "scan_progress" in line and "type" in line:
                            logger.info(f"在 {file_path} 第 {line_num} 行找到scan_progress: {line.strip()}")
                        line_num += 1
            else:
                logger.warning(f"文件不存在: {file_path}")


async def main():
    """主函数"""
    logger.info("===== 扫描进度调试开始 =====")

    debugger = ScanProgressDebugger()

    # 连接WebSocket
    if not await debugger.connect_websockets():
        logger.error("连接WebSocket失败，终止调试")
        return

    # 启动监听任务
    data_collection_listen_task = asyncio.create_task(
        debugger.listen_for_progress_events(debugger.data_collection_ws, "数据收集")
    )
    vuln_scan_listen_task = asyncio.create_task(
        debugger.listen_for_progress_events(debugger.vuln_scan_ws, "漏洞扫描")
    )

    # 发送开始扫描命令
    await debugger.send_start_scan_command()

    # 等待一些消息
    logger.info("等待5秒以接收初始消息...")
    await asyncio.sleep(5)

    # 发送测试HTTP请求模拟流量
    debugger.send_test_http_request()

    # 继续监听一段时间
    logger.info("等待20秒以接收扫描进度更新...")
    await asyncio.sleep(20)

    # 检查扫描器代码
    debugger.check_scanner_code()

    # 检查进度计算
    debugger.check_progress_calculation()

    # 生成报告
    report = debugger.generate_report()

    # 关闭WebSocket连接
    if debugger.data_collection_ws:
        await debugger.data_collection_ws.close()
    if debugger.vuln_scan_ws:
        await debugger.vuln_scan_ws.close()

    logger.info("===== 扫描进度调试完成 =====")

    # 打印检查结果和建议
    print("\n===== 检查结果 =====")
    if report['progress_analysis']['issue']:
        print(f"问题: {report['progress_analysis']['message']}")

        if report['progress_analysis']['issue'] == 'no_progress_messages':
            print("\n建议修复:")
            print("1. 检查后端的channel_layer.group_send方法是否正确调用")
            print("2. 确认scan_progress事件是否正确发送")
            print("3. 查看data_collection/scanner.py和vuln_scan/scanner.py中的进度计算代码")

        elif report['progress_analysis']['issue'] == 'progress_always_zero':
            print("\n建议修复:")
            print("1. 检查进度计算逻辑，当前进度值始终为0")
            print("2. 确认是否有正确增加progress值的代码")
            print("3. 确认进度更新是否在扫描过程中发送")
    else:
        print("WebSocket通信看起来正常，问题可能出在前端处理进度更新的代码中")
        print("\n建议检查前端代码:")
        print("1. 确认ScanProgress.vue组件中的progress属性绑定")
        print("2. 确认handleScanProgress函数是否正确更新scanProgress变量")
        print("3. 检查Vue组件的计算属性和监听器")


if __name__ == "__main__":
    asyncio.run(main())