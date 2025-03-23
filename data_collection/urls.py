from django.urls import path
from . import views

urlpatterns = [
    # 资产管理接口
    path('assets/', views.AssetList.as_view(), name='asset-list'),
    path('assets/<int:pk>/', views.AssetDetail.as_view(), name='asset-detail'),

    # 扫描结果接口
    path('scan-results/', views.ScanResultList.as_view(), name='scan-result-list'),
    path('scan-results/<int:pk>/', views.ScanResultDetail.as_view(), name='scan-result-detail'),
    path('scan-results/passive/', views.PassiveScanResultList.as_view(), name='passive-scan-result-list'),
    path('scan-results/active/', views.ActiveScanResultList.as_view(), name='active-scan-result-list'),

    # 系统设置接口
    path('settings/', views.SystemSettingsView.as_view(), name='system-settings'),

    # 跳过目标接口
    path('skip-targets/', views.SkipTargetList.as_view(), name='skip-target-list'),
    path('skip-targets/<int:pk>/', views.SkipTargetDetail.as_view(), name='skip-target-detail'),
]