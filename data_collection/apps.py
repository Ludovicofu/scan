from django.apps import AppConfig

class DataCollectionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'data_collection'
    verbose_name = '数据采集'