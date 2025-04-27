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

    # 资产标签接口
    path('tags/', views.AssetTagList.as_view(), name='tag-list'),
    path('tags/<int:pk>/', views.AssetTagDetail.as_view(), name='tag-detail'),

    # 资产分组接口
    path('groups/', views.AssetGroupList.as_view(), name='group-list'),
    path('groups/<int:pk>/', views.AssetGroupDetail.as_view(), name='group-detail'),

    # 资产统计接口
    path('statistics/', views.asset_statistics, name='asset-statistics'),

    # 资产关联管理接口
    path('assets/<int:asset_id>/add-to-group/<int:group_id>/', views.add_asset_to_group, name='add-asset-to-group'),
    path('assets/<int:asset_id>/remove-from-group/<int:group_id>/', views.remove_asset_from_group,
         name='remove-asset-from-group'),
    path('assets/<int:asset_id>/add-tag/<int:tag_id>/', views.add_tag_to_asset, name='add-tag-to-asset'),
    path('assets/<int:asset_id>/remove-tag/<int:tag_id>/', views.remove_tag_from_asset, name='remove-tag-from-asset'),
]