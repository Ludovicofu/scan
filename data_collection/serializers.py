from rest_framework import serializers
from .models import Asset, ScanResult, SystemSettings, SkipTarget


class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = '__all__'


class ScanResultSerializer(serializers.ModelSerializer):
    asset_host = serializers.CharField(source='asset.host', read_only=True)
    module_display = serializers.CharField(source='get_module_display', read_only=True)
    scan_type_display = serializers.CharField(source='get_scan_type_display', read_only=True)

    class Meta:
        model = ScanResult
        fields = '__all__'

    def to_representation(self, instance):
        """自定义展示，添加模块和扫描类型的中文名称"""
        ret = super().to_representation(instance)
        ret['module_display'] = instance.get_module_display()
        ret['scan_type_display'] = instance.get_scan_type_display()
        # 确保请求和响应数据字段被包含在序列化结果中
        ret['request_data'] = instance.request_data
        ret['response_data'] = instance.response_data
        return ret


class SystemSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemSettings
        fields = '__all__'


class SkipTargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = SkipTarget
        fields = '__all__'