from django.db import models
from django.utils import timezone


class Asset(models.Model):
    """
    资产表：存储扫描的目标资产信息
    """
    host = models.CharField(max_length=255, unique=True, verbose_name='主机名/IP')
    first_seen = models.DateTimeField(default=timezone.now, verbose_name='首次发现时间')
    last_seen = models.DateTimeField(default=timezone.now, verbose_name='最后发现时间')

    def __str__(self):
        return self.host

    class Meta:
        verbose_name = '资产'
        verbose_name_plural = '资产列表'
        ordering = ['-last_seen']


class ScanResult(models.Model):
    """
    扫描结果表：存储信息收集模块的扫描结果
    """
    MODULE_CHOICES = (
        ('network', '网络信息'),
        ('os', '操作系统信息'),
        ('component', '组件与服务信息'),
    )

    SCAN_TYPE_CHOICES = (
        ('passive', '被动扫描'),
        ('active', '主动扫描'),
    )

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='scan_results', verbose_name='资产')
    module = models.CharField(max_length=20, choices=MODULE_CHOICES, verbose_name='模块')
    scan_type = models.CharField(max_length=10, choices=SCAN_TYPE_CHOICES, verbose_name='扫描类型')
    description = models.CharField(max_length=255, verbose_name='描述')
    rule_type = models.CharField(max_length=50, verbose_name='规则类型')
    match_value = models.CharField(max_length=255, verbose_name='匹配值')  # 从TextField改为CharField
    behavior = models.TextField(blank=True, null=True, verbose_name='行为')
    scan_date = models.DateTimeField(default=timezone.now, verbose_name='扫描日期')

    def __str__(self):
        return f"{self.asset.host} - {self.description} - {self.scan_date}"

    class Meta:
        verbose_name = '扫描结果'
        verbose_name_plural = '扫描结果列表'
        ordering = ['-scan_date']
        # 确保相同资产的相同结果不会重复添加
        unique_together = ['asset', 'module', 'description', 'rule_type']


class SystemSettings(models.Model):
    """
    系统设置表：存储系统全局配置
    """
    use_proxy = models.BooleanField(default=False, verbose_name='使用代理')
    proxy_address = models.CharField(max_length=255, default='http://localhost:7890', verbose_name='代理地址')
    scan_timeout = models.IntegerField(default=10, verbose_name='扫描超时时间(秒)')
    max_concurrent_scans = models.IntegerField(default=5, verbose_name='最大并发扫描数')

    def __str__(self):
        return "系统设置"

    class Meta:
        verbose_name = '系统设置'
        verbose_name_plural = '系统设置'


class SkipTarget(models.Model):
    """
    跳过目标表：存储需要跳过扫描的目标
    """
    target = models.CharField(max_length=255, unique=True, verbose_name='目标')
    description = models.TextField(blank=True, null=True, verbose_name='描述')
    created_at = models.DateTimeField(default=timezone.now, verbose_name='创建时间')

    def __str__(self):
        return self.target

    class Meta:
        verbose_name = '跳过目标'
        verbose_name_plural = '跳过目标列表'
        ordering = ['target']