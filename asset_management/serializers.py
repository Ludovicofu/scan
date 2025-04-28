from rest_framework import serializers
from data_collection.models import Asset
from vuln_scan.models import VulnScanResult
from .models import AssetNote, AssetTag, AssetGroup


class AssetNoteSerializer(serializers.ModelSerializer):
    """资产备注序列化器"""
    asset_host = serializers.CharField(source='asset.host', read_only=True)

    class Meta:
        model = AssetNote
        fields = ['id', 'asset', 'asset_host', 'content', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']


class AssetTagSerializer(serializers.ModelSerializer):
    """资产标签序列化器"""
    asset_count = serializers.SerializerMethodField()

    class Meta:
        model = AssetTag
        fields = ['id', 'name', 'color', 'description', 'asset_count', 'created_at']
        read_only_fields = ['created_at']

    def get_asset_count(self, obj):
        """获取使用此标签的资产数量"""
        return obj.assets.count()


class AssetGroupSerializer(serializers.ModelSerializer):
    """资产分组序列化器"""
    asset_count = serializers.SerializerMethodField()

    class Meta:
        model = AssetGroup
        fields = ['id', 'name', 'description', 'asset_count', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']

    def get_asset_count(self, obj):
        """获取分组中的资产数量"""
        return obj.assets.count()


class AssetSerializer(serializers.ModelSerializer):
    """资产序列化器"""
    # 添加计数字段（非模型字段）
    info_count = serializers.SerializerMethodField()
    vuln_count = serializers.SerializerMethodField()
    tags = serializers.SerializerMethodField()
    notes = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = ['id', 'host', 'first_seen', 'last_seen', 'info_count', 'vuln_count', 'tags', 'notes']

    def get_info_count(self, obj):
        """获取信息收集结果数量"""
        return obj.scan_results.count()

    def get_vuln_count(self, obj):
        """获取漏洞检测结果数量"""
        # 通过反向关联获取漏洞检测结果数量
        return obj.vuln_scan_results.count() if hasattr(obj, 'vuln_scan_results') else 0

    def get_tags(self, obj):
        """获取资产标签"""
        if hasattr(obj, 'tags'):
            return [{'id': tag.id, 'name': tag.name, 'color': tag.color} for tag in obj.tags.all()]
        return []

    def get_notes(self, obj):
        """获取资产备注"""
        if hasattr(obj, 'notes'):
            notes = obj.notes.all().order_by('-created_at')[:3]  # 获取最新的3条备注
            return [{'id': note.id, 'content': note.content, 'created_at': note.created_at} for note in notes]
        return []


class AssetDetailSerializer(AssetSerializer):
    """资产详情序列化器"""
    groups = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = ['id', 'host', 'first_seen', 'last_seen', 'info_count', 'vuln_count', 'tags', 'notes', 'groups']

    def get_groups(self, obj):
        """获取资产分组"""
        if hasattr(obj, 'groups'):
            return [{'id': group.id, 'name': group.name} for group in obj.groups.all()]
        return []