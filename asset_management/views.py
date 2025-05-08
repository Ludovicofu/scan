from rest_framework import generics, filters, status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.db.models import Count
from data_collection.models import Asset, ScanResult
from vuln_scan.models import VulnScanResult
from vuln_scan.serializers import VulnScanResultSerializer
from data_collection.serializers import ScanResultSerializer
from .models import AssetNote
from .serializers import (
    AssetSerializer, AssetDetailSerializer, AssetNoteSerializer
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

    # 有漏洞的资产数量 - 修改查询方式，使用反向关联
    vuln_assets = Asset.objects.filter(vuln_scan_results__isnull=False).distinct().count()

    # 高危漏洞资产数量 - 修复查询方式，使用反向关联名称
    # VulnScanResult 关联到 Asset 的 related_name 是 'vuln_scan_results'
    high_risk_assets = Asset.objects.filter(vuln_scan_results__severity='high').distinct().count()

    # 返回统计数据
    return Response({
        'total_assets': total_assets,
        'recent_assets': recent_assets,
        'vuln_assets': vuln_assets,
        'high_risk_assets': high_risk_assets
    })