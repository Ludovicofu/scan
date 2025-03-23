from django.urls import re_path
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack

# 导入各应用的consumers
from data_collection import consumers as data_collection_consumers
from vuln_scan import consumers as vuln_scan_consumers
from rules import consumers as rules_consumers

websocket_urlpatterns = [
    re_path(r"^ws/data_collection/$", data_collection_consumers.DataCollectionConsumer.as_asgi()),
    re_path(r"^ws/vuln_scan/$", vuln_scan_consumers.VulnScanConsumer.as_asgi()),
    re_path(r"^ws/rules/$", rules_consumers.RulesConsumer.as_asgi()),
]

application = ProtocolTypeRouter({
    "websocket": AuthMiddlewareStack(
        URLRouter(websocket_urlpatterns)
    ),
})