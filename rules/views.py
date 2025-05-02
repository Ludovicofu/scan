from rest_framework import generics, status, filters
from rest_framework.response import Response
from django.utils import timezone
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import InfoCollectionRule, VulnScanRule

# 序列化器定义
from rest_framework import serializers


class InfoCollectionRuleSerializer(serializers.ModelSerializer):
    module_display = serializers.SerializerMethodField()
    scan_type_display = serializers.SerializerMethodField()
    rule_type_display = serializers.SerializerMethodField()

    class Meta:
        model = InfoCollectionRule
        fields = '__all__'

    def get_module_display(self, obj):
        return obj.get_module_display()

    def get_scan_type_display(self, obj):
        return obj.get_scan_type_display()

    def get_rule_type_display(self, obj):
        return obj.get_rule_type_display()


class VulnScanRuleSerializer(serializers.ModelSerializer):
    vuln_type_display = serializers.SerializerMethodField()

    class Meta:
        model = VulnScanRule
        fields = '__all__'

    def get_vuln_type_display(self, obj):
        return obj.get_vuln_type_display()


# 信息收集规则视图
class InfoCollectionRuleList(generics.ListCreateAPIView):
    queryset = InfoCollectionRule.objects.all()
    serializer_class = InfoCollectionRuleSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['description', 'match_values', 'behaviors']
    ordering_fields = ['module', 'scan_type', 'description', 'updated_at']

    def perform_create(self, serializer):
        rule = serializer.save()

        # 通知规则更新
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'rule_updates',
                {
                    'type': 'rule_update',
                    'action': 'create',
                    'rule_type': 'info_collection',
                    'rule_id': rule.id,
                    'data': InfoCollectionRuleSerializer(rule).data
                }
            )
        except Exception as e:
            # 如果通知失败，记录错误但不影响API响应
            print(f"通知规则更新失败: {str(e)}")


class InfoCollectionRuleDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = InfoCollectionRule.objects.all()
    serializer_class = InfoCollectionRuleSerializer

    def perform_update(self, serializer):
        rule = serializer.save()

        # 通知规则更新
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'rule_updates',
                {
                    'type': 'rule_update',
                    'action': 'update',
                    'rule_type': 'info_collection',
                    'rule_id': rule.id,
                    'data': InfoCollectionRuleSerializer(rule).data
                }
            )
        except Exception as e:
            # 如果通知失败，记录错误但不影响API响应
            print(f"通知规则更新失败: {str(e)}")

    def perform_destroy(self, instance):
        rule_id = instance.id
        instance.delete()

        # 通知规则删除
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'rule_updates',
                {
                    'type': 'rule_update',
                    'action': 'delete',
                    'rule_type': 'info_collection',
                    'rule_id': rule_id,
                    'data': None
                }
            )
        except Exception as e:
            # 如果通知失败，记录错误但不影响API响应
            print(f"通知规则删除失败: {str(e)}")


class InfoCollectionRuleByModule(generics.ListAPIView):
    serializer_class = InfoCollectionRuleSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['description', 'match_values', 'behaviors']
    ordering_fields = ['scan_type', 'description', 'updated_at']

    def get_queryset(self):
        module = self.kwargs['module']
        queryset = InfoCollectionRule.objects.filter(module=module)
        print(f"获取模块'{module}'的规则, 找到{queryset.count()}条")
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        print(f"返回规则数据: {serializer.data}")
        return Response(serializer.data)


class InfoCollectionRuleByModuleAndType(generics.ListAPIView):
    serializer_class = InfoCollectionRuleSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['description', 'match_values', 'behaviors']
    ordering_fields = ['description', 'updated_at']

    def get_queryset(self):
        module = self.kwargs['module']
        scan_type = self.kwargs['scan_type']
        return InfoCollectionRule.objects.filter(module=module, scan_type=scan_type)


# 漏洞检测规则视图 - 修改以移除对 scan_type 的引用
class VulnScanRuleList(generics.ListCreateAPIView):
    queryset = VulnScanRule.objects.all()
    serializer_class = VulnScanRuleSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description', 'rule_content']
    ordering_fields = ['vuln_type', 'name', 'updated_at']  # 移除 'scan_type'

    def perform_create(self, serializer):
        rule = serializer.save()

        # 通知规则更新
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'rule_updates',
                {
                    'type': 'rule_update',
                    'action': 'create',
                    'rule_type': 'vuln_scan',
                    'rule_id': rule.id,
                    'data': VulnScanRuleSerializer(rule).data
                }
            )
        except Exception as e:
            # 如果通知失败，记录错误但不影响API响应
            print(f"通知规则更新失败: {str(e)}")


class VulnScanRuleDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = VulnScanRule.objects.all()
    serializer_class = VulnScanRuleSerializer

    def perform_update(self, serializer):
        rule = serializer.save()

        # 通知规则更新
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'rule_updates',
                {
                    'type': 'rule_update',
                    'action': 'update',
                    'rule_type': 'vuln_scan',
                    'rule_id': rule.id,
                    'data': VulnScanRuleSerializer(rule).data
                }
            )
        except Exception as e:
            # 如果通知失败，记录错误但不影响API响应
            print(f"通知规则更新失败: {str(e)}")

    def perform_destroy(self, instance):
        rule_id = instance.id
        instance.delete()

        # 通知规则删除
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'rule_updates',
                {
                    'type': 'rule_update',
                    'action': 'delete',
                    'rule_type': 'vuln_scan',
                    'rule_id': rule_id,
                    'data': None
                }
            )
        except Exception as e:
            # 如果通知失败，记录错误但不影响API响应
            print(f"通知规则删除失败: {str(e)}")


class VulnScanRuleByType(generics.ListAPIView):
    serializer_class = VulnScanRuleSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description', 'rule_content']
    ordering_fields = ['name', 'updated_at']

    def get_queryset(self):
        vuln_type = self.kwargs['vuln_type']
        # 移除对scan_type的过滤
        return VulnScanRule.objects.filter(vuln_type=vuln_type)