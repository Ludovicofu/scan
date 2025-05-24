

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('data_collection', '0003_alter_scanresult_unique_together'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scanresult',
            name='match_value',
            field=models.TextField(verbose_name='匹配值'),
        ),
    ]
