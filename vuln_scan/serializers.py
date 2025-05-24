from rest_framework import serializers
from .models import VulnScanResult

class VulnScanResultSerializer(serializers.ModelSerializer):
    asset_host = serializers.CharField(source='asset.host', read_only=True)
    vuln_type_display = serializers.CharField(source='get_vuln_type_display', read_only=True)
    scan_type_display = serializers.CharField(source='get_scan_type_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)

    class Meta:
        model = VulnScanResult
        fields = '__all__'