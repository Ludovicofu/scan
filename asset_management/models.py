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