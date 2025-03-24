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

# 手动定义HTTP应用
django_application = get_asgi_application()

# 现在安全地导入WebSocket路由
import data_collection.routing
import vuln_scan.routing
import rules.routing  # 确保这行存在

# 合并所有WebSocket路由
websocket_urlpatterns = []
websocket_urlpatterns.extend(data_collection.routing.websocket_urlpatterns)
websocket_urlpatterns.extend(vuln_scan.routing.websocket_urlpatterns)
websocket_urlpatterns.extend(rules.routing.websocket_urlpatterns)  # 确保这行存在

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