from django.urls import path
from . import views

urlpatterns = [
    # 漏洞扫描结果API
    path('results/', views.VulnScanResultList.as_view(), name='vuln-scan-result-list'),
    path('results/<int:pk>/', views.VulnScanResultDetail.as_view(), name='vuln-scan-result-detail'),

    # 按漏洞类型获取结果
    path('results/type/<str:vuln_type>/', views.VulnScanResultByTypeList.as_view(), name='vuln-scan-result-by-type'),

    # 漏洞验证API
    path('results/<int:pk>/verify/', views.verify_vulnerability, name='verify-vulnerability'),
]