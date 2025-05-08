# report_management/report_generator.py
import os
import time
from datetime import datetime
from django.utils import timezone
from django.conf import settings
from xhtml2pdf import pisa
from io import BytesIO
import tempfile
from weasyprint import HTML, CSS
from data_collection.models import Asset, ScanResult
from vuln_scan.models import VulnScanResult

# 确保reports目录存在
REPORTS_DIR = os.path.join(settings.MEDIA_ROOT, 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)


class ReportGenerator:
    """改进的PDF报告生成器，解决中文乱码问题"""

    @staticmethod
    def generate_report(report, use_weasyprint=True):
        """生成报告主入口方法

        Args:
            report: Report对象
            use_weasyprint: 是否使用WeasyPrint代替xhtml2pdf (默认True)

        Returns:
            str: 生成的PDF文件路径
        """
        try:
            # 根据报告类型选择生成方法
            if report.report_type == 'asset':
                return ReportGenerator._generate_asset_report(report, use_weasyprint)
            elif report.report_type == 'vuln':
                return ReportGenerator._generate_vuln_report(report, use_weasyprint)
            else:  # comprehensive
                return ReportGenerator._generate_comprehensive_report(report, use_weasyprint)
        except Exception as e:
            raise Exception(f"报告生成失败: {str(e)}")

    @staticmethod
    def _generate_asset_report(report, use_weasyprint=True):
        """生成资产报告PDF"""
        # 获取资产数据
        assets = report.assets.all() if report.assets.exists() else Asset.objects.all()

        # 准备HTML内容
        html_content = ReportGenerator._render_asset_report_html(report, assets)

        # 生成PDF文件名
        filename = f"asset_report_{report.id}_{int(time.time())}.pdf"
        output_path = os.path.join(REPORTS_DIR, filename)

        # 使用选定的库生成PDF
        if use_weasyprint:
            return ReportGenerator._html_to_pdf_weasyprint(html_content, output_path)
        else:
            return ReportGenerator._html_to_pdf_xhtml2pdf(html_content, output_path)

    @staticmethod
    def _generate_vuln_report(report, use_weasyprint=True):
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
        html_content = ReportGenerator._render_vuln_report_html(report, vulns)

        # 生成PDF文件名
        filename = f"vuln_report_{report.id}_{int(time.time())}.pdf"
        output_path = os.path.join(REPORTS_DIR, filename)

        # 使用选定的库生成PDF
        if use_weasyprint:
            return ReportGenerator._html_to_pdf_weasyprint(html_content, output_path)
        else:
            return ReportGenerator._html_to_pdf_xhtml2pdf(html_content, output_path)

    @staticmethod
    def _generate_comprehensive_report(report, use_weasyprint=True):
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
        html_content = ReportGenerator._render_comprehensive_report_html(report, assets, vulns, info_results)

        # 生成PDF文件名
        filename = f"security_report_{report.id}_{int(time.time())}.pdf"
        output_path = os.path.join(REPORTS_DIR, filename)

        # 使用选定的库生成PDF
        if use_weasyprint:
            return ReportGenerator._html_to_pdf_weasyprint(html_content, output_path)
        else:
            return ReportGenerator._html_to_pdf_xhtml2pdf(html_content, output_path)

    @staticmethod
    def _html_to_pdf_xhtml2pdf(html_content, output_path):
        """使用xhtml2pdf将HTML内容转换为PDF

        增强中文支持的版本
        """
        # 为HTML内容添加适当的编码和字体声明
        enhanced_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                @font-face {{
                    font-family: 'SimSun';
                    src: url('{settings.STATIC_ROOT}/fonts/simsun.ttc');
                }}
                body {{
                    font-family: SimSun, Arial, sans-serif;
                }}
            </style>
        </head>
        <body>
        {html_content}
        </body>
        </html>
        """

        # 确保html_content是字符串
        if not isinstance(enhanced_html, str):
            enhanced_html = str(enhanced_html)

        # 转换HTML为PDF并直接写入文件
        with open(output_path, "wb") as result_file:
            # 转换 HTML 为 PDF
            pisa_status = pisa.CreatePDF(
                BytesIO(enhanced_html.encode("UTF-8")),  # HTML内容
                dest=result_file  # 输出文件
            )

        # 返回状态
        if not pisa_status.err:
            return output_path
        else:
            raise Exception("HTML到PDF的转换失败: " + str(pisa_status.err))

    @staticmethod
    def _html_to_pdf_weasyprint(html_content, output_path):
        """使用WeasyPrint将HTML内容转换为PDF

        WeasyPrint通常对中文有更好的支持
        """
        # 添加适当的中文字体支持
        css_content = """
        @font-face {
            font-family: 'NotoSansSC';
            src: url('/static/fonts/NotoSansCJKsc-Regular.otf') format('opentype');
            font-weight: normal;
            font-style: normal;
        }
        @font-face {
            font-family: 'NotoSansSC';
            src: url('/static/fonts/NotoSansCJKsc-Bold.otf') format('opentype');
            font-weight: bold;
            font-style: normal;
        }
        body {
            font-family: 'NotoSansSC', sans-serif;
        }
        """

        # 创建临时HTML文件
        with tempfile.NamedTemporaryFile(delete=False, suffix='.html', mode='w', encoding='utf-8') as temp:
            temp.write(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Report</title>
                <style>
                    {css_content}
                </style>
            </head>
            <body>
                {html_content}
            </body>
            </html>
            """)
            temp_path = temp.name

        try:
            # 使用WeasyPrint生成PDF
            HTML(temp_path).write_pdf(output_path)
            return output_path
        finally:
            # 删除临时文件
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    @staticmethod
    def _render_asset_report_html(report, assets):
        """渲染资产报告HTML"""
        # HTML标准头部
        html_content = f"""
        <h1>{report.title}</h1>
        <p>报告生成时间: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>{report.description or '无描述'}</p>

        <div style="background-color: #f9f9f9; padding: 10px; margin-bottom: 20px;">
            <h2>资产概述</h2>
            <p>总资产数: {assets.count()}</p>
        </div>

        <h2>资产列表</h2>
        <table border="1" style="width: 100%; border-collapse: collapse;">
            <tr style="background-color: #f2f2f2;">
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
            <div style="border: 1px solid #eee; padding: 10px; margin-bottom: 15px;">
                <div style="font-weight: bold; background-color: #f5f5f5; padding: 5px; margin-bottom: 10px;">
                    资产: {asset.host} (ID: {asset.id})
                </div>

                <h3>信息收集结果</h3>
            """

            # 获取信息收集结果
            info_results = asset.scan_results.all()

            if info_results.exists():
                html_content += """
                <table border="1" style="width: 100%; border-collapse: collapse;">
                    <tr style="background-color: #f2f2f2;">
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
                    <table border="1" style="width: 100%; border-collapse: collapse;">
                        <tr style="background-color: #f2f2f2;">
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
        <div style="text-align: center; margin-top: 30px; font-size: 10px; color: #666;">
            <p>此报告由半自动化漏洞扫描系统生成</p>
            <p>© 2025 安全检测报告</p>
        </div>
        """

        return html_content

    @staticmethod
    def _render_vuln_report_html(report, vulns):
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
        <h1>{report.title}</h1>
        <p>报告生成时间: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>{report.description or '无描述'}</p>

        <div style="background-color: #f9f9f9; padding: 10px; margin-bottom: 20px;">
            <h2>漏洞概述</h2>
            <p>总漏洞数: {vulns.count()}</p>
            <p>高危漏洞: <span style="color: #d9534f; font-weight: bold;">{high_vulns}</span></p>
            <p>中危漏洞: <span style="color: #f0ad4e; font-weight: bold;">{medium_vulns}</span></p>
            <p>低危漏洞: <span style="color: #5bc0de;">{low_vulns}</span></p>
        </div>

        <h2>漏洞类型分布</h2>
        <table border="1" style="width: 100%; border-collapse: collapse;">
            <tr style="background-color: #f2f2f2;">
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
        <table border="1" style="width: 100%; border-collapse: collapse;">
            <tr style="background-color: #f2f2f2;">
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
            severity_style = ""

            if severity == 'high' or severity == '高':
                severity_style = "color: #d9534f; font-weight: bold;"
            elif severity == 'medium' or severity == '中':
                severity_style = "color: #f0ad4e; font-weight: bold;"
            elif severity == 'low' or severity == '低':
                severity_style = "color: #5bc0de;"

            html_content += f"""
            <tr>
                <td>{vuln.id}</td>
                <td>{asset_host}</td>
                <td>{vuln.name}</td>
                <td>{vuln_type}</td>
                <td style="{severity_style}">{severity}</td>
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
            severity_style = ""

            if severity == 'high' or severity == '高':
                severity_style = "color: #d9534f; font-weight: bold;"
            elif severity == 'medium' or severity == '中':
                severity_style = "color: #f0ad4e; font-weight: bold;"
            elif severity == 'low' or severity == '低':
                severity_style = "color: #5bc0de;"

            html_content += f"""
            <div style="border: 1px solid #eee; padding: 10px; margin-bottom: 15px;">
                <div style="font-weight: bold; background-color: #f5f5f5; padding: 5px; margin-bottom: 10px;">
                    {vuln.name} (ID: {vuln.id})
                </div>
                <p><strong>资产:</strong> {asset_host}</p>
                <p><strong>类型:</strong> {vuln_type}</p>
                <p><strong>严重程度:</strong> <span style="{severity_style}">{severity}</span></p>
                <p><strong>URL:</strong> {vuln.url or '无'}</p>
                <p><strong>描述:</strong> {vuln.description or '无描述'}</p>
                <p><strong>发现时间:</strong> {vuln.scan_date.strftime('%Y-%m-%d %H:%M:%S') if vuln.scan_date else '未知'}</p>
                <p><strong>已验证:</strong> {'是' if vuln.is_verified else '否'}</p>
            </div>
            """

        # 添加页脚
        html_content += """
        <div style="text-align: center; margin-top: 30px; font-size: 10px; color: #666;">
            <p>此报告由半自动化漏洞扫描系统生成</p>
            <p>© 2025 安全检测报告</p>
        </div>
        """

        return html_content

    @staticmethod
    def _render_comprehensive_report_html(report, assets, vulns, info_results):
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
        <h1>{report.title}</h1>
        <p>报告生成时间: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>{report.description or '无描述'}</p>

        <div style="background-color: #f9f9f9; padding: 10px; margin-bottom: 20px;">
            <h2>安全概述</h2>
            <p>总资产数: {assets.count()}</p>
            <p>总漏洞数: {vulns.count()}</p>
            <p>高危漏洞: <span style="color: #d9534f; font-weight: bold;">{high_vulns}</span></p>
            <p>中危漏洞: <span style="color: #f0ad4e; font-weight: bold;">{medium_vulns}</span></p>
            <p>低危漏洞: <span style="color: #5bc0de;">{low_vulns}</span></p>
            <p>信息收集结果: {info_results.count()}</p>
        </div>

        <div style="margin-bottom: 30px;">
            <h2>漏洞类型分布</h2>
            <table border="1" style="width: 100%; border-collapse: collapse;">
                <tr style="background-color: #f2f2f2;">
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

        <div style="margin-bottom: 30px;">
            <h2>资产列表</h2>
            <table border="1" style="width: 100%; border-collapse: collapse;">
                <tr style="background-color: #f2f2f2;">
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

        <div style="margin-bottom: 30px;">
            <h2>漏洞列表</h2>
            <table border="1" style="width: 100%; border-collapse: collapse;">
                <tr style="background-color: #f2f2f2;">
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
            severity_style = ""

            if severity == 'high' or severity == '高':
                severity_style = "color: #d9534f; font-weight: bold;"
            elif severity == 'medium' or severity == '中':
                severity_style = "color: #f0ad4e; font-weight: bold;"
            elif severity == 'low' or severity == '低':
                severity_style = "color: #5bc0de;"

            html_content += f"""
                <tr>
                    <td>{vuln.id}</td>
                    <td>{asset_host}</td>
                    <td>{vuln.name}</td>
                    <td>{vuln_type}</td>
                    <td style="{severity_style}">{severity}</td>
                    <td>{vuln.url or '无'}</td>
                    <td>{vuln.scan_date.strftime('%Y-%m-%d %H:%M:%S') if vuln.scan_date else '未知'}</td>
                </tr>
            """

        html_content += """
            </table>
        </div>

        <div style="margin-bottom: 30px;">
            <h2>信息收集结果</h2>
            <table border="1" style="width: 100%; border-collapse: collapse;">
                <tr style="background-color: #f2f2f2;">
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
        <div style="margin-bottom: 30px;">
            <h2>安全建议</h2>
            <div style="background-color: #f9f9f9; padding: 15px; border-left: 3px solid #5bc0de;">
                <p>根据扫描结果，建议采取以下安全措施：</p>
                <ol>
                    <li style="margin-bottom: 10px;">优先修复高危漏洞，特别是可能导致远程代码执行的漏洞</li>
                    <li style="margin-bottom: 10px;">定期更新系统和应用程序，以修复已知的安全漏洞</li>
                    <li style="margin-bottom: 10px;">实施最小权限原则，限制用户和进程的权限</li>
                    <li style="margin-bottom: 10px;">加强网络访问控制，使用防火墙和入侵检测系统</li>
                    <li style="margin-bottom: 10px;">实施安全编码实践，预防常见的安全漏洞</li>
                    <li style="margin-bottom: 10px;">定期进行安全培训，提高安全意识</li>
                    <li style="margin-bottom: 10px;">建立安全事件响应计划，及时应对安全事件</li>
                </ol>
            </div>
        </div>

        <div style="text-align: center; margin-top: 30px; font-size: 10px; color: #666;">
            <p>此报告由半自动化漏洞扫描系统生成</p>
            <p>© 2025 安全检测报告</p>
        </div>
        """

        return html_content