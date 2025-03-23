from django.urls import path
from . import views

urlpatterns = [
    # 信息收集规则API
    path('info-collection/', views.InfoCollectionRuleList.as_view(), name='info-collection-rule-list'),
    path('info-collection/<int:pk>/', views.InfoCollectionRuleDetail.as_view(), name='info-collection-rule-detail'),
    path('info-collection/module/<str:module>/', views.InfoCollectionRuleByModule.as_view(),
         name='info-collection-rule-by-module'),
    path('info-collection/module/<str:module>/scan-type/<str:scan_type>/',
         views.InfoCollectionRuleByModuleAndType.as_view(), name='info-collection-rule-by-module-and-type'),

    # 漏洞检测规则API
    path('vuln-scan/', views.VulnScanRuleList.as_view(), name='vuln-scan-rule-list'),
    path('vuln-scan/<int:pk>/', views.VulnScanRuleDetail.as_view(), name='vuln-scan-rule-detail'),
    path('vuln-scan/type/<str:vuln_type>/', views.VulnScanRuleByType.as_view(), name='vuln-scan-rule-by-type'),
    path('vuln-scan/type/<str:vuln_type>/scan-type/<str:scan_type>/', views.VulnScanRuleByTypeAndScanType.as_view(),
         name='vuln-scan-rule-by-type-and-scan-type'),
]