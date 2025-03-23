from django.contrib import admin
from django.urls import path, include
from .views import proxy_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('data_collection/', include('data_collection.urls')),
    path('rules/', include('rules.urls')),
    path('vuln_scan/', include('vuln_scan.urls')),
    path('proxy/', proxy_view, name='proxy'),
]