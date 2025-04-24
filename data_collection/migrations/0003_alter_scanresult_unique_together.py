# Generated manually

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('data_collection', '0002_add_request_response_fields'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='scanresult',
            unique_together={('asset', 'module', 'description', 'rule_type')},
        ),
    ]