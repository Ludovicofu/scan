from django.urls import path
from . import views

urlpatterns = [
    # 漏洞扫描结果API
    path('results/', views.VulnScanResultList.as_view(), name='vuln-scan-result-list'),
    path('results/<int:pk>/', views.VulnScanResultDetail.as_view(), name='vuln-scan-result-detail'),
    path('results/passive/', views.PassiveVulnScanResultList.as_view(), name='passive-vuln-scan-result-list'),
    path('results/active/', views.ActiveVulnScanResultList.as_view(), name='active-vuln-scan-result-list'),
]