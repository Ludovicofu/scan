from django.apps import AppConfig

class VulnScanConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'vuln_scan'
    verbose_name = '漏洞检测'