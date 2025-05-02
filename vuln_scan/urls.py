# 在 vuln_scan/urls.py 中添加漏洞验证和按类型查询的路由

from django.urls import path
from . import views

urlpatterns = [
    # 漏洞扫描结果API
    path('results/', views.VulnScanResultList.as_view(), name='vuln-scan-result-list'),
    path('results/<int:pk>/', views.VulnScanResultDetail.as_view(), name='vuln-scan-result-detail'),
    path('results/passive/', views.PassiveVulnScanResultList.as_view(), name='passive-vuln-scan-result-list'),
    path('results/active/', views.ActiveVulnScanResultList.as_view(), name='active-vuln-scan-result-list'),

    # 新增 - 漏洞验证API
    path('results/<int:pk>/verify/', views.verify_vulnerability, name='verify-vulnerability'),

    # 新增 - 按漏洞类型获取结果
    path('results/type/<str:vuln_type>/', views.VulnScanResultByTypeList.as_view(), name='vuln-scan-result-by-type'),
]