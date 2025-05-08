from django.contrib import admin
from django.urls import path, include
from .views import proxy_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('data_collection/', include('data_collection.urls')),
    path('asset_management/', include('asset_management.urls')),
    path('rules/', include('rules.urls')),
    path('vuln_scan/', include('vuln_scan.urls')),
    path('report_management/', include('report_management.urls')),  # 添加报告管理URL
    path('proxy/', proxy_view, name='proxy'),  # 代理数据接收端点
]