from rest_framework import serializers
from .models import ReportTemplate, Report, ReportGenerationTask
from data_collection.models import Asset


class ReportTemplateSerializer(serializers.ModelSerializer):
    """报告模板序列化器"""

    class Meta:
        model = ReportTemplate
        fields = ['id', 'name', 'description', 'template_file', 'created_at']
        read_only_fields = ['created_at']


class ReportSerializer(serializers.ModelSerializer):
    """报告序列化器"""
    template_name = serializers.CharField(source='template.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    report_type_display = serializers.CharField(source='get_report_type_display', read_only=True)
    assets_count = serializers.IntegerField(source='assets.count', read_only=True)

    class Meta:
        model = Report
        fields = [
            'id', 'title', 'description', 'report_type', 'report_type_display',
            'template', 'template_name', 'report_file', 'status', 'status_display',
            'status_message', 'created_at', 'completed_at', 'assets_count'
        ]
        read_only_fields = ['created_at', 'completed_at', 'status', 'status_message']