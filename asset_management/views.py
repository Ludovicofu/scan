from rest_framework import generics, filters, status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.db.models import Count
from data_collection.models import Asset, ScanResult
from vuln_scan.models import VulnScanResult
from vuln_scan.serializers import VulnScanResultSerializer
from data_collection.serializers import ScanResultSerializer
from .models import AssetNote, AssetTag, AssetGroup
from .serializers import (
    AssetSerializer, AssetDetailSerializer, AssetNoteSerializer,
    AssetTagSerializer, AssetGroupSerializer
)


# 资产视图
class AssetList(generics.ListAPIView):
    """资产列表视图"""
    serializer_class = AssetSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['host']
    ordering_fields = ['last_seen', 'first_seen']
    ordering = ['-last_seen']  # 默认按最后发现时间倒序排列

    def get_queryset(self):
        queryset = Asset.objects.all()

        # 标签过滤
        tag_id = self.request.query_params.get('tag')
        if tag_id:
            queryset = queryset.filter(tags__id=tag_id)

        # 分组过滤
        group_id = self.request.query_params.get('group')
        if group_id:
            queryset = queryset.filter(groups__id=group_id)

        return queryset


class AssetDetail(generics.RetrieveUpdateDestroyAPIView):
    """资产详情视图"""
    queryset = Asset.objects.all()
    serializer_class = AssetDetailSerializer

    def perform_destroy(self, instance):
        # 删除资产时，关联的结果会通过外键关系自动删除
        instance.delete()


# 资产关联结果视图
class AssetInfoResultList(generics.ListAPIView):
    """获取资产的信息收集结果"""
    serializer_class = ScanResultSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['description', 'match_value']
    ordering_fields = ['scan_date', 'module', 'rule_type']
    ordering = ['-scan_date']  # 默认按扫描日期倒序排列

    def get_queryset(self):
        asset_id = self.kwargs['asset_id']
        return ScanResult.objects.filter(asset_id=asset_id)


class AssetVulnResultList(generics.ListAPIView):
    """获取资产的漏洞扫描结果"""
    serializer_class = VulnScanResultSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description', 'url']
    ordering_fields = ['scan_date', 'vuln_type', 'severity']
    ordering = ['-scan_date']  # 默认按扫描日期倒序排列

    def get_queryset(self):
        asset_id = self.kwargs['asset_id']
        return VulnScanResult.objects.filter(asset_id=asset_id)


# 资产备注视图
class AssetNoteList(generics.ListCreateAPIView):
    """资产备注列表视图"""
    serializer_class = AssetNoteSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['content']
    ordering_fields = ['created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        asset_id = self.kwargs.get('asset_id')
        if asset_id:
            return AssetNote.objects.filter(asset_id=asset_id)
        return AssetNote.objects.all()

    def perform_create(self, serializer):
        asset_id = self.kwargs.get('asset_id')
        if asset_id:
            serializer.save(asset_id=asset_id)
        else:
            serializer.save()


class AssetNoteDetail(generics.RetrieveUpdateDestroyAPIView):
    """资产备注详情视图"""
    queryset = AssetNote.objects.all()
    serializer_class = AssetNoteSerializer


# 资产标签视图
class AssetTagList(generics.ListCreateAPIView):
    """资产标签列表视图"""
    queryset = AssetTag.objects.all()
    serializer_class = AssetTagSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']


class AssetTagDetail(generics.RetrieveUpdateDestroyAPIView):
    """资产标签详情视图"""
    queryset = AssetTag.objects.all()
    serializer_class = AssetTagSerializer


# 资产分组视图
class AssetGroupList(generics.ListCreateAPIView):
    """资产分组列表视图"""
    queryset = AssetGroup.objects.all()
    serializer_class = AssetGroupSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']


class AssetGroupDetail(generics.RetrieveUpdateDestroyAPIView):
    """资产分组详情视图"""
    queryset = AssetGroup.objects.all()
    serializer_class = AssetGroupSerializer


# 资产统计API
@api_view(['GET'])
def asset_statistics(request):
    """资产统计API"""
    # 资产总数
    total_assets = Asset.objects.count()

    # 最近添加的资产数量(7天内)
    from django.utils import timezone
    import datetime
    recent_date = timezone.now() - datetime.timedelta(days=7)
    recent_assets = Asset.objects.filter(first_seen__gte=recent_date).count()

    # 有漏洞的资产数量
    vuln_assets = Asset.objects.filter(vuln_scan_results__isnull=False).distinct().count()

    # 高危漏洞资产数量
    high_risk_assets = Asset.objects.filter(vuln_scan_results__severity='high').distinct().count()

    # 按标签统计
    tag_stats = AssetTag.objects.annotate(asset_count=Count('assets')).values('id', 'name', 'color', 'asset_count')

    # 返回统计数据
    return Response({
        'total_assets': total_assets,
        'recent_assets': recent_assets,
        'vuln_assets': vuln_assets,
        'high_risk_assets': high_risk_assets,
        'tag_stats': tag_stats
    })


# 资产关联管理API
@api_view(['POST'])
def add_asset_to_group(request, asset_id, group_id):
    """将资产添加到分组"""
    try:
        asset = Asset.objects.get(pk=asset_id)
        group = AssetGroup.objects.get(pk=group_id)
        group.assets.add(asset)
        return Response({'status': 'success'})
    except (Asset.DoesNotExist, AssetGroup.DoesNotExist):
        return Response({'status': 'error', 'message': '资产或分组不存在'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
def remove_asset_from_group(request, asset_id, group_id):
    """从分组中移除资产"""
    try:
        asset = Asset.objects.get(pk=asset_id)
        group = AssetGroup.objects.get(pk=group_id)
        group.assets.remove(asset)
        return Response({'status': 'success'})
    except (Asset.DoesNotExist, AssetGroup.DoesNotExist):
        return Response({'status': 'error', 'message': '资产或分组不存在'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
def add_tag_to_asset(request, asset_id, tag_id):
    """为资产添加标签"""
    try:
        asset = Asset.objects.get(pk=asset_id)
        tag = AssetTag.objects.get(pk=tag_id)
        asset.tags.add(tag)
        return Response({'status': 'success'})
    except (Asset.DoesNotExist, AssetTag.DoesNotExist):
        return Response({'status': 'error', 'message': '资产或标签不存在'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
def remove_tag_from_asset(request, asset_id, tag_id):
    """从资产移除标签"""
    try:
        asset = Asset.objects.get(pk=asset_id)
        tag = AssetTag.objects.get(pk=tag_id)
        asset.tags.remove(tag)
        return Response({'status': 'success'})
    except (Asset.DoesNotExist, AssetTag.DoesNotExist):
        return Response({'status': 'error', 'message': '资产或标签不存在'}, status=status.HTTP_404_NOT_FOUND)