import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "system.settings")

# 首先设置Django，确保应用已加载
import django
django.setup()

# 然后导入其他模块
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from channels.security.websocket import AllowedHostsOriginValidator
from channels.generic.websocket import AsyncWebsocketConsumer
from django.urls import re_path

# 手动定义HTTP应用
django_application = get_asgi_application()

# 现在安全地导入WebSocket路由
import data_collection.routing
import vuln_scan.routing

# 创建一个简单的RulesConsumer来处理ws/rules/路径
class RulesConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        print("Rules WebSocket连接已接受")

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        await self.send(text_data=text_data)

# 确保合并所有WebSocket路由
websocket_urlpatterns = []
websocket_urlpatterns.extend(data_collection.routing.websocket_urlpatterns)
websocket_urlpatterns.extend(vuln_scan.routing.websocket_urlpatterns)

# 添加rules路径
websocket_urlpatterns.append(
    re_path(r"^ws/rules/$", RulesConsumer.as_asgi())
)

# 明确定义协议路由
application = ProtocolTypeRouter({
    "http": django_application,
    "websocket": AllowedHostsOriginValidator(
        AuthMiddlewareStack(
            URLRouter(
                websocket_urlpatterns
            )
        )
    ),
})