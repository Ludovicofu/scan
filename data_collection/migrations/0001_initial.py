from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Asset',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('host', models.CharField(max_length=255, unique=True, verbose_name='主机名/IP')),
                ('first_seen', models.DateTimeField(default=django.utils.timezone.now, verbose_name='首次发现时间')),
                ('last_seen', models.DateTimeField(default=django.utils.timezone.now, verbose_name='最后发现时间')),
            ],
            options={
                'verbose_name': '资产',
                'verbose_name_plural': '资产列表',
                'ordering': ['-last_seen'],
            },
        ),
        migrations.CreateModel(
            name='SkipTarget',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target', models.CharField(max_length=255, unique=True, verbose_name='目标')),
                ('description', models.TextField(blank=True, null=True, verbose_name='描述')),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, verbose_name='创建时间')),
            ],
            options={
                'verbose_name': '跳过目标',
                'verbose_name_plural': '跳过目标列表',
                'ordering': ['target'],
            },
        ),
        migrations.CreateModel(
            name='SystemSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('use_proxy', models.BooleanField(default=False, verbose_name='使用代理')),
                ('proxy_address', models.CharField(default='http://localhost:7890', max_length=255, verbose_name='代理地址')),
                ('scan_timeout', models.IntegerField(default=10, verbose_name='扫描超时时间(秒)')),
                ('max_concurrent_scans', models.IntegerField(default=5, verbose_name='最大并发扫描数')),
            ],
            options={
                'verbose_name': '系统设置',
                'verbose_name_plural': '系统设置',
            },
        ),
        migrations.CreateModel(
            name='ScanResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('module', models.CharField(choices=[('network', '网络信息'), ('os', '操作系统信息'), ('component', '组件与服务信息')], max_length=20, verbose_name='模块')),
                ('scan_type', models.CharField(choices=[('passive', '被动扫描'), ('active', '主动扫描')], max_length=10, verbose_name='扫描类型')),
                ('description', models.CharField(max_length=255, verbose_name='描述')),
                ('rule_type', models.CharField(max_length=50, verbose_name='规则类型')),
                ('match_value', models.CharField(max_length=255, verbose_name='匹配值')),
                ('behavior', models.TextField(blank=True, null=True, verbose_name='行为')),
                ('scan_date', models.DateTimeField(default=django.utils.timezone.now, verbose_name='扫描日期')),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scan_results', to='data_collection.asset', verbose_name='资产')),
            ],
            options={
                'verbose_name': '扫描结果',
                'verbose_name_plural': '扫描结果列表',
                'ordering': ['-scan_date'],
                'unique_together': {('asset', 'module', 'description', 'rule_type')},
            },
        ),
    ]
