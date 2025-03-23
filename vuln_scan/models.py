from django.db import models
from django.utils import timezone
from data_collection.models import Asset


class VulnScanResult(models.Model):
    """
    漏洞扫描结果模型
    """
    VULN_TYPE_CHOICES = (
        ('sql_injection', 'SQL注入'),
        ('xss', 'XSS跨站脚本'),
        ('file_inclusion', '文件包含'),
        ('command_injection', '命令注入'),
        ('ssrf', 'SSRF服务器端请求伪造'),
        ('xxe', 'XXE外部实体注入'),
        ('other', '其他'),
    )

    SCAN_TYPE_CHOICES = (
        ('passive', '被动扫描'),
        ('active', '主动扫描'),
    )

    SEVERITY_CHOICES = (
        ('high', '高'),
        ('medium', '中'),
        ('low', '低'),
        ('info', '信息'),
    )

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='vuln_scan_results', verbose_name='资产')
    vuln_type = models.CharField(max_length=20, choices=VULN_TYPE_CHOICES, verbose_name='漏洞类型')
    scan_type = models.CharField(max_length=10, choices=SCAN_TYPE_CHOICES, verbose_name='扫描类型')
    name = models.CharField(max_length=255, verbose_name='漏洞名称')
    description = models.TextField(verbose_name='漏洞描述')
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, verbose_name='严重程度')
    url = models.URLField(verbose_name='漏洞URL')
    request = models.TextField(blank=True, null=True, verbose_name='请求数据')
    response = models.TextField(blank=True, null=True, verbose_name='响应数据')
    proof = models.TextField(verbose_name='漏洞证明')
    scan_date = models.DateTimeField(default=timezone.now, verbose_name='扫描日期')
    is_verified = models.BooleanField(default=False, verbose_name='是否已验证')

    def __str__(self):
        return f"{self.asset.host} - {self.name} - {self.scan_date}"

    class Meta:
        verbose_name = '漏洞扫描结果'
        verbose_name_plural = '漏洞扫描结果列表'
        ordering = ['-scan_date']