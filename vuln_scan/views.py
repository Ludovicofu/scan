from rest_framework import generics, filters
from .models import VulnScanResult

# 序列化器定义
from rest_framework import serializers


class VulnScanResultSerializer(serializers.ModelSerializer):
    asset_host = serializers.CharField(source='asset.host', read_only=True)
    vuln_type_display = serializers.CharField(source='get_vuln_type_display', read_only=True)
    scan_type_display = serializers.CharField(source='get_scan_type_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)

    class Meta:
        model = VulnScanResult
        fields = '__all__'


# 漏洞扫描结果视图
class VulnScanResultList(generics.ListCreateAPIView):
    queryset = VulnScanResult.objects.all()
    serializer_class = VulnScanResultSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description', 'url']
    ordering_fields = ['scan_date', 'vuln_type', 'severity']


class VulnScanResultDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = VulnScanResult.objects.all()
    serializer_class = VulnScanResultSerializer


class PassiveVulnScanResultList(generics.ListAPIView):
    serializer_class = VulnScanResultSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description', 'url']
    ordering_fields = ['scan_date', 'vuln_type', 'severity']

    def get_queryset(self):
        return VulnScanResult.objects.filter(scan_type='passive')


class ActiveVulnScanResultList(generics.ListAPIView):
    serializer_class = VulnScanResultSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description', 'url']
    ordering_fields = ['scan_date', 'vuln_type', 'severity']

    def get_queryset(self):
        return VulnScanResult.objects.filter(scan_type='active')