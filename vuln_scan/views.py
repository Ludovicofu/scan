from rest_framework import generics, filters
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from .models import VulnScanResult

# 序列化器定义
from rest_framework import serializers


class VulnScanResultSerializer(serializers.ModelSerializer):
    asset_host = serializers.CharField(source='asset.host', read_only=True)
    vuln_type_display = serializers.CharField(source='get_vuln_type_display', read_only=True)

    class Meta:
        model = VulnScanResult
        fields = '__all__'


# 漏洞扫描结果视图
class VulnScanResultList(generics.ListCreateAPIView):
    queryset = VulnScanResult.objects.all()
    serializer_class = VulnScanResultSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description', 'url']
    ordering_fields = ['scan_date', 'vuln_type']


class VulnScanResultDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = VulnScanResult.objects.all()
    serializer_class = VulnScanResultSerializer


# 按漏洞类型获取结果视图
class VulnScanResultByTypeList(generics.ListAPIView):
    serializer_class = VulnScanResultSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description', 'url']
    ordering_fields = ['scan_date']

    def get_queryset(self):
        vuln_type = self.kwargs['vuln_type']
        return VulnScanResult.objects.filter(vuln_type=vuln_type)


# 漏洞验证视图
@api_view(['POST'])
def verify_vulnerability(request, pk):
    """验证漏洞"""
    vuln_result = get_object_or_404(VulnScanResult, pk=pk)
    vuln_result.is_verified = True
    vuln_result.save()

    # 返回成功响应
    return Response({
        'status': 'success',
        'message': '漏洞已验证'
    })