import logging
import traceback
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

# 导入报告生成器，使用try-except以防导入错误
try:
    from .report_generator import ReportGenerator

    logger = logging.getLogger(__name__)
    logger.info("成功导入ReportGenerator")
except Exception as e:
    logger = logging.getLogger(__name__)
    logger.error(f"导入ReportGenerator失败: {str(e)}")
    logger.error(traceback.format_exc())


    # 创建一个最小的报告生成器
    class ReportGenerator:
        @staticmethod
        def generate_report(report):
            logger.info("使用最小报告生成器")
            return ""

# 确保media目录存在
REPORTS_DIR = os.path.join(settings.MEDIA_ROOT, 'reports')
try:
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
        logger.info(f"创建目录: {REPORTS_DIR}")
    else:
        logger.info(f"目录已存在: {REPORTS_DIR}")
except Exception as e:
    logger.error(f"创建目录失败: {str(e)}")
    logger.error(traceback.format_exc())


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
        logger.info("开始处理报告生成请求")
        try:
            # 获取请求参数
            title = request.data.get('title', f"安全扫描报告-{datetime.now().strftime('%Y%m%d%H%M%S')}")
            description = request.data.get('description', '')
            report_type = request.data.get('report_type', 'comprehensive')
            asset_ids = request.data.get('asset_ids', [])

            logger.info(f"报告参数: title={title}, report_type={report_type}, asset_ids={asset_ids}")

            # 创建报告记录
            report = Report(
                title=title,
                description=description,
                report_type=report_type,
                status='generating'
            )

            # 先保存报告对象以获取ID
            report.save()
            logger.info(f"创建报告记录: ID={report.id}")

            # 添加资产（如果有）
            if asset_ids:
                try:
                    assets = Asset.objects.filter(id__in=asset_ids)
                    logger.info(f"找到 {assets.count()} 个资产")
                    report.assets.add(*assets)
                    logger.info("资产添加成功")
                except Exception as e:
                    logger.error(f"添加资产时出错: {str(e)}")
                    logger.error(traceback.format_exc())

            # 开始生成报告
            try:
                # 使用报告生成器
                logger.info("调用报告生成器")
                file_path = ReportGenerator.generate_report(report)
                logger.info(f"报告生成成功: {file_path}")

                # 更新报告状态
                report.status = 'completed'
                report.completed_at = timezone.now()

                # 存储相对路径作为状态消息，以便下载时使用
                report.status_message = os.path.relpath(file_path, settings.MEDIA_ROOT)
                report.save()
                logger.info("报告状态已更新为completed")

                return Response({
                    'id': report.id,
                    'status': 'success',
                    'message': '报告生成成功'
                })
            except Exception as e:
                logger.error(f"生成报告时出错: {str(e)}")
                logger.error(traceback.format_exc())
                # 发生错误，更新报告状态
                report.status = 'failed'
                report.status_message = str(e)
                report.save()
                logger.info("报告状态已更新为failed")
                return Response({
                    'status': 'error',
                    'message': f'报告生成失败: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            logger.error(f"处理报告生成请求时出错: {str(e)}")
            logger.error(traceback.format_exc())
            return Response({
                'status': 'error',
                'message': f'处理报告生成请求时出错: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'], url_path='download')
    def download(self, request, pk=None):
        """下载报告"""
        logger.info(f"开始处理报告下载请求: ID={pk}")
        try:
            report = self.get_object()
            logger.info(f"找到报告: {report.title}, 状态: {report.status}")

            if report.status != 'completed' or not report.status_message:
                logger.warning(f"报告未完成或无文件路径: status={report.status}, message={report.status_message}")
                return Response({
                    'status': 'error',
                    'message': '报告文件不存在或未生成完成'
                }, status=status.HTTP_404_NOT_FOUND)

            # 从状态消息中获取相对文件路径
            relative_path = report.status_message
            file_path = os.path.join(settings.MEDIA_ROOT, relative_path)
            logger.info(f"报告文件路径: {file_path}")

            if not os.path.exists(file_path):
                logger.warning(f"报告文件不存在: {file_path}")
                return Response({
                    'status': 'error',
                    'message': '报告文件丢失'
                }, status=status.HTTP_404_NOT_FOUND)

            try:
                # 获取文件名
                filename = os.path.basename(file_path)
                logger.info(f"准备下载文件: {filename}")

                # 打开文件并作为响应返回
                response = FileResponse(
                    open(file_path, 'rb'),
                    content_type='application/pdf'
                )
                response['Content-Disposition'] = f'attachment; filename="{filename}"'
                logger.info("文件响应已创建")
                return response
            except Exception as e:
                logger.error(f"创建下载响应时出错: {str(e)}")
                logger.error(traceback.format_exc())
                return Response({
                    'status': 'error',
                    'message': f'下载文件失败: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            logger.error(f"处理报告下载请求时出错: {str(e)}")
            logger.error(traceback.format_exc())
            return Response({
                'status': 'error',
                'message': f'处理报告下载请求时出错: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)