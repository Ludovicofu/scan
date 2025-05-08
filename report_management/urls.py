from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'templates', views.ReportTemplateViewSet)
router.register(r'reports', views.ReportViewSet)

urlpatterns = [
    path('', include(router.urls)),
    # 添加明确的报告生成路径
    path('reports/generate/', views.ReportViewSet.as_view({'post': 'generate'}), name='report-generate'),
]