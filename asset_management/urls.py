from django.urls import path
from . import views

urlpatterns = [
    # 资产管理API接口
    path('assets/', views.AssetList.as_view(), name='asset-list'),
    path('assets/<int:pk>/', views.AssetDetail.as_view(), name='asset-detail'),

    # 资产关联结果接口
    path('assets/<int:asset_id>/info-results/', views.AssetInfoResultList.as_view(), name='asset-info-results'),
    path('assets/<int:asset_id>/vuln-results/', views.AssetVulnResultList.as_view(), name='asset-vuln-results'),

    # 资产备注接口
    path('assets/<int:asset_id>/notes/', views.AssetNoteList.as_view(), name='asset-note-list'),
    path('notes/', views.AssetNoteList.as_view(), name='note-list'),
    path('notes/<int:pk>/', views.AssetNoteDetail.as_view(), name='note-detail'),

    # 资产统计接口
    path('statistics/', views.asset_statistics, name='asset-statistics'),
]