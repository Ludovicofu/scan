# Generated manually

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0002_add_port_rule_type'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='vulnscanrule',
            name='scan_type',
        ),
    ]