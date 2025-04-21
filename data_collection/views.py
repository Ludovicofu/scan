from rest_framework import generics, status, views
from rest_framework.response import Response
from .models import Asset, ScanResult, SystemSettings, SkipTarget
from django.utils import timezone
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import json

# 序列化器定义
from rest_framework import serializers


class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = '__all__'


class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = '__all__'

    def to_representation(self, instance):
        """自定义展示，添加模块和扫描类型的中文名称"""
        ret = super().to_representation(instance)
        ret['module_display'] = instance.get_module_display()
        ret['scan_type_display'] = instance.get_scan_type_display()
        # 确保请求和响应数据字段被包含在序列化结果中
        ret['request_data'] = instance.request_data
        ret['response_data'] = instance.response_data
        return ret


class SystemSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemSettings
        fields = '__all__'


class SkipTargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = SkipTarget
        fields = '__all__'


# 资产视图
class AssetList(generics.ListCreateAPIView):
    queryset = Asset.objects.all()
    serializer_class = AssetSerializer

    def perform_create(self, serializer):
        serializer.save()


class AssetDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Asset.objects.all()
    serializer_class = AssetSerializer


# 扫描结果视图
class ScanResultList(generics.ListCreateAPIView):
    queryset = ScanResult.objects.all()
    serializer_class = ScanResultSerializer

    def perform_create(self, serializer):
        serializer.save()


class ScanResultDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = ScanResult.objects.all()
    serializer_class = ScanResultSerializer


class PassiveScanResultList(generics.ListAPIView):
    serializer_class = ScanResultSerializer

    def get_queryset(self):
        return ScanResult.objects.filter(scan_type='passive')


class ActiveScanResultList(generics.ListAPIView):
    serializer_class = ScanResultSerializer

    def get_queryset(self):
        return ScanResult.objects.filter(scan_type='active')


# 系统设置视图
class SystemSettingsView(views.APIView):
    def get(self, request):
        # 获取系统设置（总是获取ID为1的记录，如果不存在则创建）
        settings, created = SystemSettings.objects.get_or_create(pk=1)
        serializer = SystemSettingsSerializer(settings)
        return Response(serializer.data)

    def put(self, request):
        # 更新系统设置
        settings, created = SystemSettings.objects.get_or_create(pk=1)
        serializer = SystemSettingsSerializer(settings, data=request.data)
        if serializer.is_valid():
            serializer.save()

            # 通知mitmproxy脚本更新设置
            try:
                channel_layer = get_channel_layer()
                async_to_sync(channel_layer.group_send)(
                    'settings_update',
                    {
                        'type': 'settings_update',
                        'data': serializer.data
                    }
                )
            except Exception as e:
                # 如果通知失败，记录错误但不影响API响应
                print(f"通知设置更新失败: {str(e)}")

            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# 跳过目标视图
class SkipTargetList(generics.ListCreateAPIView):
    queryset = SkipTarget.objects.all()
    serializer_class = SkipTargetSerializer

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        print(f"返回跳过目标数据: {serializer.data}")
        return Response(serializer.data)

    def perform_create(self, serializer):
        target = serializer.save()

        # 通知WebSocket客户端更新跳过目标列表
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'settings_update',
                {
                    'type': 'skip_target_update',
                    'action': 'add',
                    'target': target.target
                }
            )
        except Exception as e:
            # 如果通知失败，记录错误但不影响API响应
            print(f"通知跳过目标添加失败: {str(e)}")


class SkipTargetDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = SkipTarget.objects.all()
    serializer_class = SkipTargetSerializer

    def perform_destroy(self, instance):
        target = instance.target
        instance.delete()

        # 通知WebSocket客户端更新跳过目标列表
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'settings_update',
                {
                    'type': 'skip_target_update',
                    'action': 'remove',
                    'target': target
                }
            )
        except Exception as e:
            # 如果通知失败，记录错误但不影响API响应
            print(f"通知跳过目标删除失败: {str(e)}")