

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('data_collection', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanresult',
            name='request_data',
            field=models.TextField(blank=True, null=True, verbose_name='请求数据'),
        ),
        migrations.AddField(
            model_name='scanresult',
            name='response_data',
            field=models.TextField(blank=True, null=True, verbose_name='响应数据'),
        ),
    ]