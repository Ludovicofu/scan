from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from django.http import FileResponse
from django.utils import timezone
from django.conf import settings
import os
import tempfile
from datetime import datetime
import time
from xhtml2pdf import pisa
from io import BytesIO

from .models import ReportTemplate, Report
from .serializers import ReportTemplateSerializer, ReportSerializer
from data_collection.models import Asset, ScanResult
from vuln_scan.models import VulnScanResult

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

    # 修改action装饰器，确保detail=False且url_path正确设置
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
            # 根据报告类型选择生成方法
            if report_type == 'asset':
                file_path = self.generate_asset_report(report)
            elif report_type == 'vuln':
                file_path = self.generate_vuln_report(report)
            else:  # comprehensive
                file_path = self.generate_comprehensive_report(report)

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

    def html_to_pdf(self, html_content, output_path):
        """将HTML内容转换为PDF并保存到指定路径"""
        # 确保html_content是字符串
        if not isinstance(html_content, str):
            html_content = str(html_content)

        # 转换HTML为PDF并直接写入文件
        with open(output_path, "wb") as result_file:
            # 转换 HTML 为 PDF
            pisa_status = pisa.CreatePDF(
                BytesIO(html_content.encode("UTF-8")),  # HTML内容
                dest=result_file  # 输出文件
            )

        # 返回状态
        if not pisa_status.err:
            return output_path
        else:
            raise Exception("HTML到PDF的转换失败: " + str(pisa_status.err))

    def generate_asset_report(self, report):
        """生成资产报告PDF"""
        # 获取资产数据
        assets = report.assets.all() if report.assets.exists() else Asset.objects.all()

        # 准备HTML内容
        html_content = self.render_asset_report_html(report, assets)

        # 生成PDF文件名
        filename = f"asset_report_{report.id}_{int(time.time())}.pdf"
        output_path = os.path.join(REPORTS_DIR, filename)

        # 转换HTML到PDF
        return self.html_to_pdf(html_content, output_path)

    def render_asset_report_html(self, report, assets):
        """渲染资产报告HTML"""
        # 添加报告标题和基本信息
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>{report.title}</title>
            <style>
                @page {{
                    size: A4;
                    margin: 1cm;
                }}
                body {{
                    font-family: SimSun, Arial, sans-serif;
                    font-size: 12px;
                    line-height: 1.4;
                    color: #333;
                }}
                h1, h2, h3, h4 {{
                    color: #1a1a1a;
                }}
                h1 {{
                    font-size: 24px;
                    text-align: center;
                    margin-bottom: 20px;
                }}
                h2 {{
                    font-size: 18px;
                    border-bottom: 1px solid #ddd;
                    padding-bottom: 5px;
                    margin-top: 20px;
                }}
                h3 {{
                    font-size: 16px;
                    margin-top: 15px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }}
                table, th, td {{
                    border: 1px solid #ddd;
                }}
                th, td {{
                    padding: 8px;
                    text-align: left;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 30px;
                    font-size: 10px;
                    color: #666;
                }}
                .summary {{
                    background-color: #f9f9f9;
                    padding: 10px;
                    margin-bottom: 20px;
                }}
                .asset-block {{
                    border: 1px solid #eee;
                    padding: 10px;
                    margin-bottom: 15px;
                }}
                .asset-title {{
                    font-weight: bold;
                    background-color: #f5f5f5;
                    padding: 5px;
                    margin-bottom: 10px;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{report.title}</h1>
                <p>报告生成时间: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>{report.description or '无描述'}</p>
            </div>

            <div class="summary">
                <h2>资产概述</h2>
                <p>总资产数: {assets.count()}</p>
            </div>

            <h2>资产列表</h2>
        """

        # 添加资产列表表格
        html_content += """
            <table>
                <tr>
                    <th>ID</th>
                    <th>主机</th>
                    <th>首次发现</th>
                    <th>最后发现</th>
                    <th>信息收集结果数</th>
                    <th>漏洞数量</th>
                </tr>
        """

        # 添加资产数据行
        for asset in assets:
            info_count = asset.scan_results.count()
            vuln_count = asset.vuln_scan_results.count() if hasattr(asset, 'vuln_scan_results') else 0

            html_content += f"""
                <tr>
                    <td>{asset.id}</td>
                    <td>{asset.host}</td>
                    <td>{asset.first_seen.strftime('%Y-%m-%d %H:%M:%S') if asset.first_seen else '未知'}</td>
                    <td>{asset.last_seen.strftime('%Y-%m-%d %H:%M:%S') if asset.last_seen else '未知'}</td>
                    <td>{info_count}</td>
                    <td>{vuln_count}</td>
                </tr>
            """

        html_content += """
            </table>

            <h2>资产详情</h2>
        """

        # 添加每个资产的详细信息
        for asset in assets:
            html_content += f"""
            <div class="asset-block">
                <div class="asset-title">资产: {asset.host} (ID: {asset.id})</div>

                <h3>信息收集结果</h3>
            """

            # 获取信息收集结果
            info_results = asset.scan_results.all()

            if info_results.exists():
                html_content += """
                <table>
                    <tr>
                        <th>ID</th>
                        <th>模块</th>
                        <th>描述</th>
                        <th>扫描时间</th>
                    </tr>
                """

                for info in info_results[:20]:  # 限制为20条
                    module = info.get_module_display() if hasattr(info, 'get_module_display') else info.module

                    html_content += f"""
                    <tr>
                        <td>{info.id}</td>
                        <td>{module}</td>
                        <td>{info.description}</td>
                        <td>{info.scan_date.strftime('%Y-%m-%d %H:%M:%S') if info.scan_date else '未知'}</td>
                    </tr>
                    """

                html_content += """
                </table>
                """

                # 如果结果太多，显示提示
                if info_results.count() > 20:
                    html_content += f"<p>只显示了前20条记录，总共有 {info_results.count()} 条信息收集结果。</p>"
            else:
                html_content += "<p>暂无信息收集结果</p>"

            # 获取漏洞结果
            if hasattr(asset, 'vuln_scan_results'):
                vuln_results = asset.vuln_scan_results.all()

                html_content += "<h3>漏洞检测结果</h3>"

                if vuln_results.exists():
                    html_content += """
                    <table>
                        <tr>
                            <th>ID</th>
                            <th>漏洞名称</th>
                            <th>漏洞类型</th>
                            <th>严重程度</th>
                            <th>URL</th>
                            <th>扫描时间</th>
                        </tr>
                    """

                    for vuln in vuln_results[:10]:  # 限制为10条
                        vuln_type = vuln.get_vuln_type_display() if hasattr(vuln,
                                                                            'get_vuln_type_display') else vuln.vuln_type
                        severity = vuln.get_severity_display() if hasattr(vuln,
                                                                          'get_severity_display') else vuln.severity

                        html_content += f"""
                        <tr>
                            <td>{vuln.id}</td>
                            <td>{vuln.name}</td>
                            <td>{vuln_type}</td>
                            <td>{severity}</td>
                            <td>{vuln.url or '无'}</td>
                            <td>{vuln.scan_date.strftime('%Y-%m-%d %H:%M:%S') if vuln.scan_date else '未知'}</td>
                        </tr>
                        """

                    html_content += """
                    </table>
                    """

                    # 如果结果太多，显示提示
                    if vuln_results.count() > 10:
                        html_content += f"<p>只显示了前10条记录，总共有 {vuln_results.count()} 条漏洞检测结果。</p>"
                else:
                    html_content += "<p>暂无漏洞检测结果</p>"

            html_content += """
            </div>
            """

        # 添加页脚
        html_content += """
            <div class="footer">
                <p>此报告由半自动化漏洞扫描系统生成</p>
                <p>© 2025 安全检测报告</p>
            </div>
        </body>
        </html>
        """

        return html_content

    def generate_vuln_report(self, report):
        """生成漏洞报告PDF"""
        # 获取相关资产
        assets = report.assets.all() if report.assets.exists() else Asset.objects.all()
        asset_ids = [asset.id for asset in assets]

        # 获取漏洞数据
        if asset_ids:
            vulns = VulnScanResult.objects.filter(asset_id__in=asset_ids)
        else:
            vulns = VulnScanResult.objects.all()

        # 准备HTML内容
        html_content = self.render_vuln_report_html(report, vulns)

        # 生成PDF文件名
        filename = f"vuln_report_{report.id}_{int(time.time())}.pdf"
        output_path = os.path.join(REPORTS_DIR, filename)

        # 转换HTML到PDF
        return self.html_to_pdf(html_content, output_path)

    def render_vuln_report_html(self, report, vulns):
        """渲染漏洞报告HTML"""
        # 漏洞统计
        high_vulns = vulns.filter(severity='high').count()
        medium_vulns = vulns.filter(severity='medium').count()
        low_vulns = vulns.filter(severity='low').count()

        # 按类型统计漏洞
        vuln_types = {}
        for vuln in vulns:
            vuln_type = vuln.get_vuln_type_display() if hasattr(vuln, 'get_vuln_type_display') else vuln.vuln_type
            if vuln_type in vuln_types:
                vuln_types[vuln_type] += 1
            else:
                vuln_types[vuln_type] = 1

        # 创建HTML内容
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>{report.title}</title>
            <style>
                @page {{
                    size: A4;
                    margin: 1cm;
                }}
                body {{
                    font-family: SimSun, Arial, sans-serif;
                    font-size: 12px;
                    line-height: 1.4;
                    color: #333;
                }}
                h1, h2, h3, h4 {{
                    color: #1a1a1a;
                }}
                h1 {{
                    font-size: 24px;
                    text-align: center;
                    margin-bottom: 20px;
                }}
                h2 {{
                    font-size: 18px;
                    border-bottom: 1px solid #ddd;
                    padding-bottom: 5px;
                    margin-top: 20px;
                }}
                h3 {{
                    font-size: 16px;
                    margin-top: 15px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }}
                table, th, td {{
                    border: 1px solid #ddd;
                }}
                th, td {{
                    padding: 8px;
                    text-align: left;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 30px;
                    font-size: 10px;
                    color: #666;
                }}
                .summary {{
                    background-color: #f9f9f9;
                    padding: 10px;
                    margin-bottom: 20px;
                }}
                .vuln-block {{
                    border: 1px solid #eee;
                    padding: 10px;
                    margin-bottom: 15px;
                }}
                .vuln-title {{
                    font-weight: bold;
                    background-color: #f5f5f5;
                    padding: 5px;
                    margin-bottom: 10px;
                }}
                .high-severity {{
                    color: #d9534f;
                    font-weight: bold;
                }}
                .medium-severity {{
                    color: #f0ad4e;
                    font-weight: bold;
                }}
                .low-severity {{
                    color: #5bc0de;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{report.title}</h1>
                <p>报告生成时间: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>{report.description or '无描述'}</p>
            </div>

            <div class="summary">
                <h2>漏洞概述</h2>
                <p>总漏洞数: {vulns.count()}</p>
                <p>高危漏洞: <span class="high-severity">{high_vulns}</span></p>
                <p>中危漏洞: <span class="medium-severity">{medium_vulns}</span></p>
                <p>低危漏洞: <span class="low-severity">{low_vulns}</span></p>
            </div>

            <h2>漏洞类型分布</h2>
            <table>
                <tr>
                    <th>漏洞类型</th>
                    <th>数量</th>
                </tr>
        """

        # 添加漏洞类型统计
        for vuln_type, count in vuln_types.items():
            html_content += f"""
                <tr>
                    <td>{vuln_type}</td>
                    <td>{count}</td>
                </tr>
            """

        html_content += """
            </table>

            <h2>漏洞列表</h2>
            <table>
                <tr>
                    <th>ID</th>
                    <th>资产</th>
                    <th>漏洞名称</th>
                    <th>类型</th>
                    <th>严重程度</th>
                    <th>URL</th>
                    <th>发现时间</th>
                    <th>已验证</th>
                </tr>
        """

        # 添加漏洞数据行
        for vuln in vulns:
            asset_host = vuln.asset.host if vuln.asset else "未知"
            vuln_type = vuln.get_vuln_type_display() if hasattr(vuln, 'get_vuln_type_display') else vuln.vuln_type
            severity = vuln.get_severity_display() if hasattr(vuln, 'get_severity_display') else vuln.severity
            severity_class = ""

            if severity == 'high' or severity == '高':
                severity_class = "high-severity"
            elif severity == 'medium' or severity == '中':
                severity_class = "medium-severity"
            elif severity == 'low' or severity == '低':
                severity_class = "low-severity"

            html_content += f"""
                <tr>
                    <td>{vuln.id}</td>
                    <td>{asset_host}</td>
                    <td>{vuln.name}</td>
                    <td>{vuln_type}</td>
                    <td class="{severity_class}">{severity}</td>
                    <td>{vuln.url or '无'}</td>
                    <td>{vuln.scan_date.strftime('%Y-%m-%d %H:%M:%S') if vuln.scan_date else '未知'}</td>
                    <td>{'是' if vuln.is_verified else '否'}</td>
                </tr>
            """

        html_content += """
            </table>

            <h2>漏洞详情</h2>
        """

        # 添加每个漏洞的详细信息
        for vuln in vulns:
            asset_host = vuln.asset.host if vuln.asset else "未知"
            vuln_type = vuln.get_vuln_type_display() if hasattr(vuln, 'get_vuln_type_display') else vuln.vuln_type
            severity = vuln.get_severity_display() if hasattr(vuln, 'get_severity_display') else vuln.severity
            severity_class = ""

            if severity == 'high' or severity == '高':
                severity_class = "high-severity"
            elif severity == 'medium' or severity == '中':
                severity_class = "medium-severity"
            elif severity == 'low' or severity == '低':
                severity_class = "low-severity"

            html_content += f"""
            <div class="vuln-block">
                <div class="vuln-title">{vuln.name} (ID: {vuln.id})</div>
                <p><strong>资产:</strong> {asset_host}</p>
                <p><strong>类型:</strong> {vuln_type}</p>
                <p><strong>严重程度:</strong> <span class="{severity_class}">{severity}</span></p>
                <p><strong>URL:</strong> {vuln.url or '无'}</p>
                <p><strong>描述:</strong> {vuln.description or '无描述'}</p>
                <p><strong>发现时间:</strong> {vuln.scan_date.strftime('%Y-%m-%d %H:%M:%S') if vuln.scan_date else '未知'}</p>
                <p><strong>已验证:</strong> {'是' if vuln.is_verified else '否'}</p>
            </div>
            """

        # 添加页脚
        html_content += """
            <div class="footer">
                <p>此报告由半自动化漏洞扫描系统生成</p>
                <p>© 2025 安全检测报告</p>
            </div>
        </body>
        </html>
        """

        return html_content

    def generate_comprehensive_report(self, report):
        """生成综合报告PDF"""
        # 获取相关资产
        assets = report.assets.all() if report.assets.exists() else Asset.objects.all()
        asset_ids = [asset.id for asset in assets]

        # 获取漏洞数据和信息收集结果
        if asset_ids:
            vulns = VulnScanResult.objects.filter(asset_id__in=asset_ids)
            info_results = ScanResult.objects.filter(asset_id__in=asset_ids)
        else:
            vulns = VulnScanResult.objects.all()
            info_results = ScanResult.objects.all()

        # 准备HTML内容
        html_content = self.render_comprehensive_report_html(report, assets, vulns, info_results)

        # 生成PDF文件名
        filename = f"security_report_{report.id}_{int(time.time())}.pdf"
        output_path = os.path.join(REPORTS_DIR, filename)

        # 转换HTML到PDF
        return self.html_to_pdf(html_content, output_path)

    def render_comprehensive_report_html(self, report, assets, vulns, info_results):
        """渲染综合报告HTML"""
        # 漏洞统计
        high_vulns = vulns.filter(severity='high').count()
        medium_vulns = vulns.filter(severity='medium').count()
        low_vulns = vulns.filter(severity='low').count()

        # 漏洞类型统计
        vuln_types = {}
        for vuln in vulns:
            vuln_type = vuln.get_vuln_type_display() if hasattr(vuln, 'get_vuln_type_display') else vuln.vuln_type
            if vuln_type in vuln_types:
                vuln_types[vuln_type] += 1
            else:
                vuln_types[vuln_type] = 1

        # 创建HTML内容
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>{report.title}</title>
            <style>
                @page {{
                    size: A4;
                    margin: 1cm;
                }}
                body {{
                    font-family: SimSun, Arial, sans-serif;
                    font-size: 12px;
                    line-height: 1.4;
                    color: #333;
                }}
                h1, h2, h3, h4 {{
                    color: #1a1a1a;
                }}
                h1 {{
                    font-size: 24px;
                    text-align: center;
                    margin-bottom: 20px;
                }}
                h2 {{
                    font-size: 18px;
                    border-bottom: 1px solid #ddd;
                    padding-bottom: 5px;
                    margin-top: 20px;
                }}
                h3 {{
                    font-size: 16px;
                    margin-top: 15px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }}
                table, th, td {{
                    border: 1px solid #ddd;
                }}
                th, td {{
                    padding: 8px;
                    text-align: left;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 30px;
                    font-size: 10px;
                    color: #666;
                }}
                .summary {{
                    background-color: #f9f9f9;
                    padding: 10px;
                    margin-bottom: 20px;
                }}
                .high-severity {{
                    color: #d9534f;
                    font-weight: bold;
                }}
                .medium-severity {{
                    color: #f0ad4e;
                    font-weight: bold;
                }}
                .low-severity {{
                    color: #5bc0de;
                }}
                .section {{
                    margin-bottom: 30px;
                }}
                .recommendations {{
                    background-color: #f9f9f9;
                    padding: 15px;
                    border-left: 3px solid #5bc0de;
                }}
                .recommendations li {{
                    margin-bottom: 10px;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{report.title}</h1>
                <p>报告生成时间: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>{report.description or '无描述'}</p>
            </div>

            <div class="summary">
                <h2>安全概述</h2>
                <p>总资产数: {assets.count()}</p>
                <p>总漏洞数: {vulns.count()}</p>
                <p>高危漏洞: <span class="high-severity">{high_vulns}</span></p>
                <p>中危漏洞: <span class="medium-severity">{medium_vulns}</span></p>
                <p>低危漏洞: <span class="low-severity">{low_vulns}</span></p>
                <p>信息收集结果: {info_results.count()}</p>
            </div>

            <div class="section">
                <h2>漏洞类型分布</h2>
                <table>
                    <tr>
                        <th>漏洞类型</th>
                        <th>数量</th>
                    </tr>
        """

        # 添加漏洞类型统计
        for vuln_type, count in vuln_types.items():
            html_content += f"""
                    <tr>
                        <td>{vuln_type}</td>
                        <td>{count}</td>
                    </tr>
            """

        html_content += """
                </table>
            </div>

            <div class="section">
                <h2>资产列表</h2>
                <table>
                    <tr>
                        <th>ID</th>
                        <th>主机</th>
                        <th>首次发现</th>
                        <th>最后发现</th>
                        <th>信息收集结果数</th>
                        <th>漏洞数量</th>
                    </tr>
        """

        # 添加资产数据行
        for asset in assets:
            info_count = asset.scan_results.count()
            vuln_count = asset.vuln_scan_results.count() if hasattr(asset, 'vuln_scan_results') else 0

            html_content += f"""
                    <tr>
                        <td>{asset.id}</td>
                        <td>{asset.host}</td>
                        <td>{asset.first_seen.strftime('%Y-%m-%d %H:%M:%S') if asset.first_seen else '未知'}</td>
                        <td>{asset.last_seen.strftime('%Y-%m-%d %H:%M:%S') if asset.last_seen else '未知'}</td>
                        <td>{info_count}</td>
                        <td>{vuln_count}</td>
                    </tr>
            """

        html_content += """
                </table>
            </div>

            <div class="section">
                <h2>漏洞列表</h2>
                <table>
                    <tr>
                        <th>ID</th>
                        <th>资产</th>
                        <th>漏洞名称</th>
                        <th>类型</th>
                        <th>严重程度</th>
                        <th>URL</th>
                        <th>发现时间</th>
                    </tr>
        """

        # 添加漏洞数据行
        for vuln in vulns:
            asset_host = vuln.asset.host if vuln.asset else "未知"
            vuln_type = vuln.get_vuln_type_display() if hasattr(vuln, 'get_vuln_type_display') else vuln.vuln_type
            severity = vuln.get_severity_display() if hasattr(vuln, 'get_severity_display') else vuln.severity
            severity_class = ""

            if severity == 'high' or severity == '高':
                severity_class = "high-severity"
            elif severity == 'medium' or severity == '中':
                severity_class = "medium-severity"
            elif severity == 'low' or severity == '低':
                severity_class = "low-severity"

            html_content += f"""
                    <tr>
                        <td>{vuln.id}</td>
                        <td>{asset_host}</td>
                        <td>{vuln.name}</td>
                        <td>{vuln_type}</td>
                        <td class="{severity_class}">{severity}</td>
                        <td>{vuln.url or '无'}</td>
                        <td>{vuln.scan_date.strftime('%Y-%m-%d %H:%M:%S') if vuln.scan_date else '未知'}</td>
                    </tr>
            """

        html_content += """
                </table>
            </div>

            <div class="section">
                <h2>信息收集结果</h2>
                <table>
                    <tr>
                        <th>ID</th>
                        <th>资产</th>
                        <th>模块</th>
                        <th>描述</th>
                        <th>扫描时间</th>
                    </tr>
        """

        # 添加信息收集数据行，限制为100条
        for i, info in enumerate(info_results.order_by('-scan_date')[:100]):
            asset_host = info.asset.host if info.asset else "未知"
            module = info.get_module_display() if hasattr(info, 'get_module_display') else info.module

            html_content += f"""
                    <tr>
                        <td>{info.id}</td>
                        <td>{asset_host}</td>
                        <td>{module}</td>
                        <td>{info.description}</td>
                        <td>{info.scan_date.strftime('%Y-%m-%d %H:%M:%S') if info.scan_date else '未知'}</td>
                    </tr>
            """

        # 如果结果太多，显示提示
        if info_results.count() > 100:
            html_content += f"""
                </table>
                <p>只显示了前100条记录，总共有 {info_results.count()} 条信息收集结果。</p>
            """
        else:
            html_content += """
                </table>
            """

        # 添加安全建议
        html_content += """
            <div class="section">
                <h2>安全建议</h2>
                <div class="recommendations">
                    <p>根据扫描结果，建议采取以下安全措施：</p>
                    <ol>
                        <li>优先修复高危漏洞，特别是可能导致远程代码执行的漏洞</li>
                        <li>定期更新系统和应用程序，以修复已知的安全漏洞</li>
                        <li>实施最小权限原则，限制用户和进程的权限</li>
                        <li>加强网络访问控制，使用防火墙和入侵检测系统</li>
                        <li>实施安全编码实践，预防常见的安全漏洞</li>
                        <li>定期进行安全培训，提高安全意识</li>
                        <li>建立安全事件响应计划，及时应对安全事件</li>
                    </ol>
                </div>
            </div>

            <div class="footer">
                <p>此报告由半自动化漏洞扫描系统生成</p>
                <p>© 2025 安全检测报告</p>
            </div>
        </body>
        </html>
        """

        return html_content