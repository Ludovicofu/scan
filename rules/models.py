from django.db import models
from django.utils import timezone


class InfoCollectionRule(models.Model):
    """
    信息收集规则模型
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

    RULE_TYPE_CHOICES = (
        ('status_code', '状态码判断'),
        ('response_content', '响应内容匹配'),
        ('header', 'HTTP 头匹配'),
        ('port', '端口扫描'),  # 新增端口扫描类型
    )

    module = models.CharField(max_length=20, choices=MODULE_CHOICES, verbose_name='模块')
    scan_type = models.CharField(max_length=10, choices=SCAN_TYPE_CHOICES, verbose_name='扫描类型')
    description = models.CharField(max_length=255, verbose_name='描述')
    rule_type = models.CharField(max_length=20, choices=RULE_TYPE_CHOICES, verbose_name='规则类型')
    match_values = models.TextField(verbose_name='匹配值')
    behaviors = models.TextField(blank=True, null=True, verbose_name='行为')
    is_enabled = models.BooleanField(default=True, verbose_name='是否启用')
    created_at = models.DateTimeField(default=timezone.now, verbose_name='创建时间')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='更新时间')

    def __str__(self):
        return f"{self.get_module_display()} - {self.description}"

    class Meta:
        verbose_name = '信息收集规则'
        verbose_name_plural = '信息收集规则列表'
        ordering = ['module', 'scan_type', 'description']


class VulnScanRule(models.Model):
    """
    漏洞检测规则模型
    """
    # 这里先定义一个基本的模型，后期可以根据需要扩展

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

    vuln_type = models.CharField(max_length=20, choices=VULN_TYPE_CHOICES, verbose_name='漏洞类型')
    scan_type = models.CharField(max_length=10, choices=SCAN_TYPE_CHOICES, verbose_name='扫描类型')
    name = models.CharField(max_length=255, verbose_name='漏洞名称')
    description = models.TextField(verbose_name='漏洞描述')
    rule_content = models.TextField(verbose_name='规则内容')
    is_enabled = models.BooleanField(default=True, verbose_name='是否启用')
    created_at = models.DateTimeField(default=timezone.now, verbose_name='创建时间')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='更新时间')

    def __str__(self):
        return f"{self.vuln_type} - {self.name}"

    class Meta:
        verbose_name = '漏洞检测规则'
        verbose_name_plural = '漏洞检测规则列表'
        ordering = ['vuln_type', 'name']