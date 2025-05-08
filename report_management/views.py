# report_management/views.py (更新版)
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from django.http import FileResponse
from django.utils import timezone
from django.conf import settings
import os
from datetime import datetime

from .models import ReportTemplate, Report
from .serializers import ReportTemplateSerializer, ReportSerializer
from data_collection.models import Asset
from .report_generator import ReportGenerator  # 导入新的报告生成器

# 确保media目录存在
REPORTS_DIR = os.path.join(settings.MEDIA_ROOT, 'reports')
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR, exist_ok=True)


class ReportTemplateViewSet(viewsets.ModelViewSet):
    """报告模板视图集"""
    queryset = ReportTemplate.objects.all()
    serializer_class = ReportTemplateSerializer
    parser_classes = (MultiPartParser, FormParser)


class ReportViewSet(viewsets.ModelViewSet):
    """报告视图集"""
    queryset = Report.objects.all().order_by('-created_at')
    serializer_class = ReportSerializer

    @action(detail=False, methods=['post'], url_path='generate')
    def generate(self, request):
        """生成报告"""
        title = request.data.get('title', f"安全扫描报告-{datetime.now().strftime('%Y%m%d%H%M%S')}")
        description = request.data.get('description', '')
        report_type = request.data.get('report_type', 'comprehensive')
        asset_ids = request.data.get('asset_ids', [])

        # 创建报告记录
        report = Report(
            title=title,
            description=description,
            report_type=report_type,
            status='generating'
        )

        # 先保存报告对象以获取ID
        report.save()

        # 添加资产（如果有）
        if asset_ids:
            assets = Asset.objects.filter(id__in=asset_ids)
            report.assets.add(*assets)

        # 开始生成报告
        try:
            # 使用新的报告生成器，默认使用WeasyPrint
            file_path = ReportGenerator.generate_report(report, use_weasyprint=True)

            # 更新报告状态
            report.status = 'completed'
            report.completed_at = timezone.now()

            # 存储相对路径作为状态消息，以便下载时使用
            report.status_message = os.path.relpath(file_path, settings.MEDIA_ROOT)
            report.save()

            return Response({
                'id': report.id,
                'status': 'success',
                'message': '报告生成成功'
            })
        except Exception as e:
            # 发生错误，更新报告状态
            report.status = 'failed'
            report.status_message = str(e)
            report.save()
            return Response({
                'status': 'error',
                'message': f'报告生成失败: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'], url_path='download')
    def download(self, request, pk=None):
        """下载报告"""
        report = self.get_object()

        if report.status != 'completed' or not report.status_message:
            return Response({
                'status': 'error',
                'message': '报告文件不存在或未生成完成'
            }, status=status.HTTP_404_NOT_FOUND)

        # 从状态消息中获取相对文件路径
        relative_path = report.status_message
        file_path = os.path.join(settings.MEDIA_ROOT, relative_path)

        if not os.path.exists(file_path):
            return Response({
                'status': 'error',
                'message': '报告文件丢失'
            }, status=status.HTTP_404_NOT_FOUND)

        try:
            # 获取文件名
            filename = os.path.basename(file_path)

            # 打开文件并作为响应返回
            response = FileResponse(
                open(file_path, 'rb'),
                content_type='application/pdf'
            )
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f'下载文件失败: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)