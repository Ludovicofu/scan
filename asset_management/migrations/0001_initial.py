# Generated manually

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('data_collection', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AssetTag',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50, unique=True, verbose_name='标签名称')),
                ('color', models.CharField(default='#409EFF', max_length=20, verbose_name='标签颜色')),
                ('description', models.CharField(blank=True, max_length=255, null=True, verbose_name='描述')),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, verbose_name='创建时间')),
                ('assets', models.ManyToManyField(related_name='tags', to='data_collection.asset', verbose_name='资产')),
            ],
            options={
                'verbose_name': '资产标签',
                'verbose_name_plural': '资产标签列表',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='AssetGroup',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True, verbose_name='分组名称')),
                ('description', models.TextField(blank=True, null=True, verbose_name='分组描述')),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, verbose_name='创建时间')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='更新时间')),
                ('assets', models.ManyToManyField(related_name='groups', to='data_collection.asset', verbose_name='资产')),
            ],
            options={
                'verbose_name': '资产分组',
                'verbose_name_plural': '资产分组列表',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='AssetNote',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('content', models.TextField(verbose_name='备注内容')),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, verbose_name='创建时间')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='更新时间')),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notes', to='data_collection.asset', verbose_name='资产')),
            ],
            options={
                'verbose_name': '资产备注',
                'verbose_name_plural': '资产备注列表',
                'ordering': ['-created_at'],
            },
        ),
    ]