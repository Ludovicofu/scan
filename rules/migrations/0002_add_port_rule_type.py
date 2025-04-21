# Generated manually

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='infocollectionrule',
            name='rule_type',
            field=models.CharField(
                choices=[
                    ('status_code', '状态码判断'),
                    ('response_content', '响应内容匹配'),
                    ('header', 'HTTP 头匹配'),
                    ('port', '端口扫描'),
                ],
                max_length=20,
                verbose_name='规则类型'
            ),
        ),
    ]