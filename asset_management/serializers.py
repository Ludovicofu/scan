from rest_framework import serializers
from data_collection.models import Asset
from vuln_scan.models import VulnScanResult
from .models import AssetNote


class AssetNoteSerializer(serializers.ModelSerializer):
    """资产备注序列化器"""
    asset_host = serializers.CharField(source='asset.host', read_only=True)

    class Meta:
        model = AssetNote
        fields = ['id', 'asset', 'asset_host', 'content', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']


class AssetSerializer(serializers.ModelSerializer):
    """资产序列化器"""
    # 添加计数字段（非模型字段）
    info_count = serializers.SerializerMethodField()
    vuln_count = serializers.SerializerMethodField()
    notes = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = ['id', 'host', 'first_seen', 'last_seen', 'info_count', 'vuln_count', 'notes']

    def get_info_count(self, obj):
        """获取信息收集结果数量"""
        return obj.scan_results.count()

    def get_vuln_count(self, obj):
        """获取漏洞检测结果数量"""
        # 通过反向关联获取漏洞检测结果数量
        return obj.vuln_scan_results.count() if hasattr(obj, 'vuln_scan_results') else 0

    def get_notes(self, obj):
        """获取资产备注"""
        if hasattr(obj, 'notes'):
            notes = obj.notes.all().order_by('-created_at')[:3]  # 获取最新的3条备注
            return [{'id': note.id, 'content': note.content, 'created_at': note.created_at} for note in notes]
        return []


class AssetDetailSerializer(AssetSerializer):
    """资产详情序列化器"""

    class Meta:
        model = Asset
        fields = ['id', 'host', 'first_seen', 'last_seen', 'info_count', 'vuln_count', 'notes']