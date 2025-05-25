
import os
import time
import logging
from datetime import datetime
from django.utils import timezone
from django.conf import settings
from django.db.models import Count, Q
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import inch, cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from io import BytesIO
import platform

# 配置日志
logger = logging.getLogger(__name__)

# 确保reports目录存在
REPORTS_DIR = os.path.join(settings.MEDIA_ROOT, 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)


class ReportGenerator:
    """修复查询错误的报告生成器"""

    @staticmethod
    def generate_report(report):
        """生成报告主入口方法"""
        try:
            # 生成PDF文件名
            filename = f"security_report_{report.id}_{int(time.time())}.pdf"
            output_path = os.path.join(REPORTS_DIR, filename)

            # 创建PDF
            ReportGenerator._create_detailed_pdf(report, output_path)

            return output_path
        except Exception as e:
            logger.error(f"报告生成失败: {str(e)}")
            logger.error(f"错误详情:", exc_info=True)
            raise Exception(f"报告生成失败: {str(e)}")

    @staticmethod
    def _create_detailed_pdf(report, output_path):
        """使用ReportLab创建详细PDF，支持中文"""
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            # 注册字体
            if platform.system() == 'Windows':
                try:
                    font_path = "C:\\Windows\\Fonts\\simsun.ttc"
                    pdfmetrics.registerFont(TTFont('SimSun', font_path))
                    pdfmetrics.registerFont(TTFont('SimSunBd', "C:\\Windows\\Fonts\\simhei.ttf"))  # 使用黑体作为粗体
                except Exception as e:
                    logger.error(f"注册字体失败: {str(e)}")
                    # 如果注册失败，使用默认字体

            # 创建文档
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )

            # 创建样式
            styles = getSampleStyleSheet()
            styles.add(ParagraphStyle(
                name='ChineseTitle',
                fontName='SimSunBd',
                fontSize=18,
                alignment=1,  # 居中
                spaceAfter=12
            ))
            styles.add(ParagraphStyle(
                name='ChineseHeading1',
                fontName='SimSunBd',
                fontSize=16,
                spaceAfter=10
            ))
            styles.add(ParagraphStyle(
                name='ChineseHeading2',
                fontName='SimSunBd',
                fontSize=14,
                spaceAfter=8
            ))
            styles.add(ParagraphStyle(
                name='ChineseNormal',
                fontName='SimSun',
                fontSize=10,
                spaceAfter=6
            ))
            styles.add(ParagraphStyle(
                name='ChineseSmall',
                fontName='SimSun',
                fontSize=8,
                spaceAfter=3
            ))

            # 开始构建内容
            story = []

            # 添加标题
            title = Paragraph(report.title, styles['ChineseTitle'])
            story.append(title)
            story.append(Spacer(1, 0.1 * inch))

            # 添加报告基本信息
            basic_info = [
                Paragraph(f"报告生成时间: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['ChineseNormal']),
                Paragraph(f"报告描述: {report.description or '无描述'}", styles['ChineseNormal']),
                Paragraph(
                    f"报告类型: {report.get_report_type_display() if hasattr(report, 'get_report_type_display') else report.report_type}",
                    styles['ChineseNormal'])
            ]
            for info in basic_info:
                story.append(info)

            story.append(Spacer(1, 0.2 * inch))

            # 添加安全概述
            story.append(Paragraph("安全概述", styles['ChineseHeading1']))
            story.append(Spacer(1, 0.1 * inch))

            # 导入必要的模型
            try:
                from data_collection.models import ScanResult, Asset
                from vuln_scan.models import VulnScanResult

                # 获取资产信息
                if report.assets.exists():
                    assets = report.assets.all()
                    asset_ids = [asset.id for asset in assets]

                    story.append(Paragraph(f"资产信息:", styles['ChineseHeading2']))

                    # 创建资产表格
                    asset_data = [['ID', '主机', '首次发现', '最后发现', '信息收集结果', '漏洞数量']]

                    for asset in assets:
                        # 获取此资产的信息收集结果和漏洞数量
                        try:
                            info_count = ScanResult.objects.filter(asset=asset).count()
                        except Exception:
                            info_count = 0

                        try:
                            vuln_count = VulnScanResult.objects.filter(asset=asset).count()
                        except Exception:
                            vuln_count = 0

                        asset_data.append([
                            str(asset.id),
                            asset.host,
                            asset.first_seen.strftime('%Y-%m-%d %H:%M:%S') if asset.first_seen else '未知',
                            asset.last_seen.strftime('%Y-%m-%d %H:%M:%S') if asset.last_seen else '未知',
                            str(info_count),
                            str(vuln_count)
                        ])

                    # 创建表格
                    if len(asset_data) > 1:  # 确保有数据行
                        asset_table = Table(asset_data, repeatRows=1)
                        asset_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('FONTNAME', (0, 0), (-1, 0), 'SimSunBd'),
                            ('FONTNAME', (0, 1), (-1, -1), 'SimSun'),
                            ('FONTSIZE', (0, 0), (-1, -1), 9),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        story.append(asset_table)
                    else:
                        story.append(Paragraph("无资产数据", styles['ChineseNormal']))

                    # 首先获取统计信息，再获取详细结果
                    # 信息收集统计
                    try:
                        # 首先进行分组统计
                        info_module_stats = ScanResult.objects.filter(asset_id__in=asset_ids).values('module').annotate(
                            count=Count('id'))

                        network_count = 0
                        os_count = 0
                        component_count = 0

                        for stat in info_module_stats:
                            if stat['module'] == 'network':
                                network_count = stat['count']
                            elif stat['module'] == 'os':
                                os_count = stat['count']
                            elif stat['module'] == 'component':
                                component_count = stat['count']

                        total_info_count = sum(item['count'] for item in info_module_stats)

                        info_stats = [
                            f"网络信息: {network_count}条",
                            f"操作系统信息: {os_count}条",
                            f"组件与服务信息: {component_count}条",
                            f"总计: {total_info_count}条"
                        ]

                        story.append(Paragraph("信息收集统计:", styles['ChineseHeading2']))
                        for stat in info_stats:
                            story.append(Paragraph(f"• {stat}", styles['ChineseNormal']))

                        story.append(Spacer(1, 0.1 * inch))

                        # 获取信息收集详细结果（在统计之后）
                        info_results = ScanResult.objects.filter(asset_id__in=asset_ids).order_by('-scan_date')[:30]
                    except Exception as e:
                        logger.error(f"获取信息收集统计时出错: {str(e)}")
                        info_results = []

                    # 漏洞统计
                    try:
                        # 按严重程度统计
                        vuln_severity_stats = VulnScanResult.objects.filter(asset_id__in=asset_ids).values(
                            'severity').annotate(count=Count('id'))

                        high_count = 0
                        medium_count = 0
                        low_count = 0

                        for stat in vuln_severity_stats:
                            if stat['severity'] == 'high':
                                high_count = stat['count']
                            elif stat['severity'] == 'medium':
                                medium_count = stat['count']
                            elif stat['severity'] == 'low':
                                low_count = stat['count']

                        # 按类型统计
                        vuln_type_stats = VulnScanResult.objects.filter(asset_id__in=asset_ids).values(
                            'vuln_type').annotate(count=Count('id'))

                        sql_count = 0
                        xss_count = 0
                        file_count = 0
                        rce_count = 0
                        ssrf_count = 0

                        for stat in vuln_type_stats:
                            if stat['vuln_type'] == 'sql_injection':
                                sql_count = stat['count']
                            elif stat['vuln_type'] == 'xss':
                                xss_count = stat['count']
                            elif stat['vuln_type'] == 'file_inclusion':
                                file_count = stat['count']
                            elif stat['vuln_type'] == 'command_injection':
                                rce_count = stat['count']
                            elif stat['vuln_type'] == 'ssrf':
                                ssrf_count = stat['count']

                        total_vuln_count = sum(item['count'] for item in vuln_severity_stats)

                        vuln_stats = [
                            f"高危漏洞: {high_count}个",
                            f"中危漏洞: {medium_count}个",
                            f"低危漏洞: {low_count}个",
                            f"SQL注入: {sql_count}个",
                            f"XSS跨站脚本: {xss_count}个",
                            f"文件包含: {file_count}个",
                            f"命令注入: {rce_count}个",
                            f"SSRF: {ssrf_count}个",
                            f"总计: {total_vuln_count}个"
                        ]

                        story.append(Paragraph("漏洞扫描统计:", styles['ChineseHeading2']))
                        for stat in vuln_stats:
                            story.append(Paragraph(f"• {stat}", styles['ChineseNormal']))

                        story.append(Spacer(1, 0.1 * inch))

                        # 获取漏洞详细结果（在统计之后）
                        vuln_results = VulnScanResult.objects.filter(asset_id__in=asset_ids).order_by('-scan_date')[:20]
                    except Exception as e:
                        logger.error(f"获取漏洞统计时出错: {str(e)}")
                        vuln_results = []
                else:
                    # 没有指定资产，获取所有数据
                    all_assets = Asset.objects.all()

                    story.append(Paragraph(f"资产统计:", styles['ChineseHeading2']))
                    story.append(Paragraph(f"• 总资产数: {all_assets.count()}个", styles['ChineseNormal']))

                    # 信息收集统计
                    try:
                        # 先获取统计信息
                        info_module_stats = ScanResult.objects.values('module').annotate(count=Count('id'))

                        network_count = 0
                        os_count = 0
                        component_count = 0

                        for stat in info_module_stats:
                            if stat['module'] == 'network':
                                network_count = stat['count']
                            elif stat['module'] == 'os':
                                os_count = stat['count']
                            elif stat['module'] == 'component':
                                component_count = stat['count']

                        total_info_count = sum(item['count'] for item in info_module_stats)

                        info_stats = [
                            f"网络信息: {network_count}条",
                            f"操作系统信息: {os_count}条",
                            f"组件与服务信息: {component_count}条",
                            f"总计: {total_info_count}条"
                        ]

                        story.append(Paragraph("信息收集统计:", styles['ChineseHeading2']))
                        for stat in info_stats:
                            story.append(Paragraph(f"• {stat}", styles['ChineseNormal']))

                        story.append(Spacer(1, 0.1 * inch))

                        # 获取详细结果（在统计之后）
                        info_results = ScanResult.objects.order_by('-scan_date')[:30]
                    except Exception as e:
                        logger.error(f"获取所有信息收集统计时出错: {str(e)}")
                        info_results = []

                    # 漏洞统计
                    try:
                        # 按严重程度统计
                        vuln_severity_stats = VulnScanResult.objects.values('severity').annotate(count=Count('id'))

                        high_count = 0
                        medium_count = 0
                        low_count = 0

                        for stat in vuln_severity_stats:
                            if stat['severity'] == 'high':
                                high_count = stat['count']
                            elif stat['severity'] == 'medium':
                                medium_count = stat['count']
                            elif stat['severity'] == 'low':
                                low_count = stat['count']

                        # 按类型统计
                        vuln_type_stats = VulnScanResult.objects.values('vuln_type').annotate(count=Count('id'))

                        sql_count = 0
                        xss_count = 0
                        file_count = 0
                        rce_count = 0
                        ssrf_count = 0

                        for stat in vuln_type_stats:
                            if stat['vuln_type'] == 'sql_injection':
                                sql_count = stat['count']
                            elif stat['vuln_type'] == 'xss':
                                xss_count = stat['count']
                            elif stat['vuln_type'] == 'file_inclusion':
                                file_count = stat['count']
                            elif stat['vuln_type'] == 'command_injection':
                                rce_count = stat['count']
                            elif stat['vuln_type'] == 'ssrf':
                                ssrf_count = stat['count']

                        total_vuln_count = sum(item['count'] for item in vuln_severity_stats)

                        vuln_stats = [
                            f"高危漏洞: {high_count}个",
                            f"中危漏洞: {medium_count}个",
                            f"低危漏洞: {low_count}个",
                            f"SQL注入: {sql_count}个",
                            f"XSS跨站脚本: {xss_count}个",
                            f"文件包含: {file_count}个",
                            f"命令注入: {rce_count}个",
                            f"SSRF: {ssrf_count}个",
                            f"总计: {total_vuln_count}个"
                        ]

                        story.append(Paragraph("漏洞扫描统计:", styles['ChineseHeading2']))
                        for stat in vuln_stats:
                            story.append(Paragraph(f"• {stat}", styles['ChineseNormal']))

                        story.append(Spacer(1, 0.1 * inch))

                        # 获取详细结果（在统计之后）
                        vuln_results = VulnScanResult.objects.order_by('-scan_date')[:20]
                    except Exception as e:
                        logger.error(f"获取所有漏洞统计时出错: {str(e)}")
                        vuln_results = []
            except Exception as e:
                logger.error(f"获取基本数据时出错: {str(e)}")
                info_results = []
                vuln_results = []

            story.append(Spacer(1, 0.3 * inch))

            # 添加详细的信息收集结果
            try:
                if 'info_results' in locals() and info_results and len(info_results) > 0:
                    story.append(Paragraph("信息收集详细结果", styles['ChineseHeading1']))

                    # 创建表格数据
                    info_data = [['ID', '资产', '模块', '描述', '扫描时间']]

                    for info in info_results:
                        try:
                            asset_host = info.asset.host if info.asset else "未知"
                            module = info.get_module_display() if hasattr(info, 'get_module_display') else info.module

                            info_data.append([
                                str(info.id),
                                asset_host,
                                module,
                                info.description[:50] + ('...' if len(info.description) > 50 else ''),  # 截断过长描述
                                info.scan_date.strftime('%Y-%m-%d %H:%M:%S') if info.scan_date else '未知'
                            ])
                        except Exception as e:
                            logger.error(f"处理信息收集结果时出错: {str(e)}")
                            continue

                    # 创建表格
                    if len(info_data) > 1:  # 确保有数据行
                        info_table = Table(info_data, repeatRows=1)
                        info_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('FONTNAME', (0, 0), (-1, 0), 'SimSunBd'),
                            ('FONTNAME', (0, 1), (-1, -1), 'SimSun'),
                            ('FONTSIZE', (0, 0), (-1, -1), 8),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black),
                            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
                        ]))
                        story.append(info_table)

                        # 如果有更多结果，显示提示
                        if len(info_results) >= 30:
                            story.append(Spacer(1, 0.1 * inch))
                            story.append(Paragraph(f"（仅显示前30条记录）", styles['ChineseSmall']))

                story.append(Spacer(1, 0.3 * inch))
            except Exception as e:
                logger.error(f"添加信息收集详细结果时出错: {str(e)}")

            # 添加详细的漏洞扫描结果
            try:
                if 'vuln_results' in locals() and vuln_results and len(vuln_results) > 0:
                    story.append(Paragraph("漏洞扫描详细结果", styles['ChineseHeading1']))

                    # 创建表格数据
                    vuln_data = [['ID', '资产', '漏洞名称', '类型', '严重程度', 'URL']]

                    for vuln in vuln_results:
                        try:
                            asset_host = vuln.asset.host if vuln.asset else "未知"
                            vuln_type = vuln.get_vuln_type_display() if hasattr(vuln,
                                                                                'get_vuln_type_display') else vuln.vuln_type
                            severity = vuln.get_severity_display() if hasattr(vuln,
                                                                              'get_severity_display') else vuln.severity

                            # 截断过长的URL
                            url_display = vuln.url
                            if url_display and len(url_display) > 30:
                                url_display = url_display[:30] + '...'

                            vuln_data.append([
                                str(vuln.id),
                                asset_host,
                                vuln.name[:30] + ('...' if len(vuln.name) > 30 else ''),  # 截断过长名称
                                vuln_type,
                                severity,
                                url_display or '无'
                            ])
                        except Exception as e:
                            logger.error(f"处理漏洞扫描结果时出错: {str(e)}")
                            continue

                    # 创建表格
                    if len(vuln_data) > 1:  # 确保有数据行
                        vuln_table = Table(vuln_data, repeatRows=1)
                        vuln_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('FONTNAME', (0, 0), (-1, 0), 'SimSunBd'),
                            ('FONTNAME', (0, 1), (-1, -1), 'SimSun'),
                            ('FONTSIZE', (0, 0), (-1, -1), 8),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black),
                            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
                        ]))
                        story.append(vuln_table)

                        # 如果有更多结果，显示提示
                        if len(vuln_results) >= 20:
                            story.append(Spacer(1, 0.1 * inch))
                            story.append(Paragraph(f"（仅显示前20条记录）", styles['ChineseSmall']))

                story.append(Spacer(1, 0.3 * inch))
            except Exception as e:
                logger.error(f"添加漏洞扫描详细结果时出错: {str(e)}")

            # 添加安全建议
            story.append(Paragraph("安全建议", styles['ChineseHeading1']))

            security_tips = [
                "定期更新系统和应用程序，以修复已知的安全漏洞",
                "实施最小权限原则，限制用户和进程的权限",
                "加强网络访问控制，使用防火墙和入侵检测系统",
                "实施安全编码实践，预防常见的安全漏洞",
                "定期进行安全培训，提高安全意识",
                "建立安全事件响应计划，及时应对安全事件"
            ]

            for tip in security_tips:
                story.append(Paragraph(f"- {tip}", styles['ChineseNormal']))

            # 构建PDF文档
            doc.build(story, onFirstPage=ReportGenerator._add_page_number,
                      onLaterPages=ReportGenerator._add_page_number)

            return True
        except Exception as e:
            logger.error(f"创建PDF失败: {str(e)}")
            logger.error(f"错误详情:", exc_info=True)
            raise

    @staticmethod
    def _add_page_number(canvas, doc):
        """添加页码和页脚"""
        canvas.saveState()
        canvas.setFont('SimSun', 8)

        # 添加页码
        page_num = canvas.getPageNumber()
        text = f"第 {page_num} 页"
        canvas.drawRightString(
            doc.pagesize[0] - 72,
            72 / 2,
            text
        )

        # 添加页脚
        footer_text = "此报告由半自动化漏洞扫描系统生成  © 2025 安全检测报告"
        canvas.drawCentredString(
            doc.pagesize[0] / 2,
            72 / 4,
            footer_text
        )

        # 添加页眉
        header_text = "安全扫描报告"
        canvas.drawCentredString(
            doc.pagesize[0] / 2,
            doc.pagesize[1] - 40,
            header_text
        )

        # 添加下划线
        canvas.line(72, 55, doc.pagesize[0] - 72, 55)

        canvas.restoreState()