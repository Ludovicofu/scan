from django.db import models
from django.utils import timezone
from data_collection.models import Asset

class AssetNote(models.Model):
    """
    资产备注：存储与资产相关的管理备注
    """
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='notes', verbose_name='资产')
    content = models.TextField(verbose_name='备注内容')
    created_at = models.DateTimeField(default=timezone.now, verbose_name='创建时间')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='更新时间')

    def __str__(self):
        return f"{self.asset.host} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"

    class Meta:
        verbose_name = '资产备注'
        verbose_name_plural = '资产备注列表'
        ordering = ['-created_at']


class AssetTag(models.Model):
    """
    资产标签：对资产进行分类标记
    """
    name = models.CharField(max_length=50, unique=True, verbose_name='标签名称')
    color = models.CharField(max_length=20, default='#409EFF', verbose_name='标签颜色')
    description = models.CharField(max_length=255, blank=True, null=True, verbose_name='描述')
    assets = models.ManyToManyField(Asset, related_name='tags', verbose_name='资产')
    created_at = models.DateTimeField(default=timezone.now, verbose_name='创建时间')

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = '资产标签'
        verbose_name_plural = '资产标签列表'
        ordering = ['name']


class AssetGroup(models.Model):
    """
    资产分组：对资产进行分组管理
    """
    name = models.CharField(max_length=100, unique=True, verbose_name='分组名称')
    description = models.TextField(blank=True, null=True, verbose_name='分组描述')
    assets = models.ManyToManyField(Asset, related_name='groups', verbose_name='资产')
    created_at = models.DateTimeField(default=timezone.now, verbose_name='创建时间')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='更新时间')

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = '资产分组'
        verbose_name_plural = '资产分组列表'
        ordering = ['name']