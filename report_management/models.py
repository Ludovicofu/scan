from django.db import models
from django.utils import timezone
from data_collection.models import Asset
import uuid
import os


def report_file_path(instance, filename):
    """为报告文件生成唯一文件名"""
    ext = filename.split('.')[-1]
    filename = f"{uuid.uuid4().hex}.{ext}"
    return os.path.join('reports', filename)


class ReportTemplate(models.Model):
    """报告模板"""
    name = models.CharField(max_length=100, verbose_name='模板名称')
    description = models.TextField(blank=True, null=True, verbose_name='模板描述')
    template_file = models.FileField(upload_to='report_templates/', verbose_name='模板文件')
    created_at = models.DateTimeField(default=timezone.now, verbose_name='创建时间')

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = '报告模板'
        verbose_name_plural = '报告模板列表'


class Report(models.Model):
    """安全检测报告"""
    REPORT_TYPE_CHOICES = (
        ('asset', '资产报告'),
        ('vuln', '漏洞报告'),
        ('comprehensive', '综合报告'),
    )

    STATUS_CHOICES = (
        ('generating', '生成中'),
        ('completed', '已完成'),
        ('failed', '失败'),
    )

    title = models.CharField(max_length=200, verbose_name='报告标题')
    description = models.TextField(blank=True, null=True, verbose_name='报告描述')
    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES, verbose_name='报告类型')
    template = models.ForeignKey(ReportTemplate, on_delete=models.SET_NULL, null=True, blank=True,
                                 verbose_name='使用模板')

    # 关联资产（可选，多对多关系）
    assets = models.ManyToManyField(Asset, related_name='reports', blank=True, verbose_name='相关资产')

    # 报告内容
    report_file = models.FileField(upload_to=report_file_path, null=True, blank=True, verbose_name='报告文件')

    # 状态跟踪
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='generating', verbose_name='状态')
    status_message = models.TextField(blank=True, null=True, verbose_name='状态信息')

    # 时间戳
    created_at = models.DateTimeField(default=timezone.now, verbose_name='创建时间')
    completed_at = models.DateTimeField(null=True, blank=True, verbose_name='完成时间')

    def __str__(self):
        return self.title

    class Meta:
        verbose_name = '安全检测报告'
        verbose_name_plural = '安全检测报告列表'
        ordering = ['-created_at']

    def mark_completed(self, file_path=None):
        """标记报告为已完成"""
        self.status = 'completed'
        self.completed_at = timezone.now()
        if file_path:
            self.report_file = file_path
        self.save()

    def mark_failed(self, message):
        """标记报告为失败"""
        self.status = 'failed'
        self.status_message = message
        self.save()


# 报告生成任务记录
class ReportGenerationTask(models.Model):
    """报告生成任务记录"""
    report = models.OneToOneField(Report, on_delete=models.CASCADE, related_name='generation_task',
                                  verbose_name='关联报告')
    task_id = models.CharField(max_length=100, blank=True, null=True, verbose_name='任务ID')
    created_at = models.DateTimeField(default=timezone.now, verbose_name='创建时间')

    def __str__(self):
        return f"Task for {self.report.title}"

    class Meta:
        verbose_name = '报告生成任务'
        verbose_name_plural = '报告生成任务列表'