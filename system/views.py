import json
import asyncio
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


@csrf_exempt
def proxy_view(request):
    """
    接收来自mitmproxy的HTTP请求和响应数据，并发送到WebSocket通道
    """
    if request.method == 'POST':
        try:
            # 解析请求数据
            data = json.loads(request.body)

            # 检查是否包含所需的字段
            required_fields = ['url', 'method', 'req_headers', 'req_content',
                               'status_code', 'resp_headers', 'resp_content', 'response_time']

            if not all(key in data for key in required_fields):
                return JsonResponse({'status': 'error', 'message': '缺少必要字段'}, status=400)

            # 获取channel layer
            channel_layer = get_channel_layer()

            # 打印关键信息以便调试
            print(f"收到代理数据，URL: {data['url']}, 方法: {data['method']}, 状态码: {data['status_code']}")

            # 异步发送数据到data_collection_scanner通道组
            async_to_sync(channel_layer.group_send)(
                'data_collection_scanner',
                {
                    'type': 'proxy_data',
                    'data': data
                }
            )

            # 异步发送数据到vuln_scan_scanner通道组
            async_to_sync(channel_layer.group_send)(
                'vuln_scan_scanner',
                {
                    'type': 'proxy_data',
                    'data': data
                }
            )

            print("代理数据已发送到WebSocket通道")

            return JsonResponse({'status': 'success'})
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': '无效的JSON数据'}, status=400)
        except Exception as e:
            print(f"proxy_view处理出错: {str(e)}")
            import traceback
            traceback.print_exc()
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    else:
        return JsonResponse({'status': 'error', 'message': '仅支持POST请求'}, status=405)