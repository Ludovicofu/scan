# Generated by Django 4.2.7 on 2025-03-23 05:33

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='InfoCollectionRule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('module', models.CharField(choices=[('network', '网络信息'), ('os', '操作系统信息'), ('component', '组件与服务信息')], max_length=20, verbose_name='模块')),
                ('scan_type', models.CharField(choices=[('passive', '被动扫描'), ('active', '主动扫描')], max_length=10, verbose_name='扫描类型')),
                ('description', models.CharField(max_length=255, verbose_name='描述')),
                ('rule_type', models.CharField(choices=[('status_code', '状态码判断'), ('response_content', '响应内容匹配'), ('header', 'HTTP 头匹配')], max_length=20, verbose_name='规则类型')),
                ('match_values', models.TextField(verbose_name='匹配值')),
                ('behaviors', models.TextField(blank=True, null=True, verbose_name='行为')),
                ('is_enabled', models.BooleanField(default=True, verbose_name='是否启用')),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, verbose_name='创建时间')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='更新时间')),
            ],
            options={
                'verbose_name': '信息收集规则',
                'verbose_name_plural': '信息收集规则列表',
                'ordering': ['module', 'scan_type', 'description'],
            },
        ),
        migrations.CreateModel(
            name='VulnScanRule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('vuln_type', models.CharField(choices=[('sql_injection', 'SQL注入'), ('xss', 'XSS跨站脚本'), ('file_inclusion', '文件包含'), ('command_injection', '命令注入'), ('ssrf', 'SSRF服务器端请求伪造'), ('xxe', 'XXE外部实体注入'), ('other', '其他')], max_length=20, verbose_name='漏洞类型')),
                ('scan_type', models.CharField(choices=[('passive', '被动扫描'), ('active', '主动扫描')], max_length=10, verbose_name='扫描类型')),
                ('name', models.CharField(max_length=255, verbose_name='漏洞名称')),
                ('description', models.TextField(verbose_name='漏洞描述')),
                ('rule_content', models.TextField(verbose_name='规则内容')),
                ('is_enabled', models.BooleanField(default=True, verbose_name='是否启用')),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, verbose_name='创建时间')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='更新时间')),
            ],
            options={
                'verbose_name': '漏洞检测规则',
                'verbose_name_plural': '漏洞检测规则列表',
                'ordering': ['vuln_type', 'name'],
            },
        ),
    ]
