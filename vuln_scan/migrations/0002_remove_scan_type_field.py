# Generated manually

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vuln_scan', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='vulnscanresult',
            name='scan_type',
        ),
    ]