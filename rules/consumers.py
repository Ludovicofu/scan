import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import InfoCollectionRule, VulnScanRule


class RuleConsumer(AsyncWebsocketConsumer):
    """
    WebSocket消费者：处理规则的WebSocket连接
    """

    async def connect(self):
        """处理WebSocket连接"""
        # 将客户端添加到rule_updates组
        await self.channel_layer.group_add(
            'rule_updates',
            self.channel_name
        )

        # 接受WebSocket连接
        await self.accept()

        # 发送当前规则
        await self.send_current_rules()

    async def disconnect(self, close_code):
        """处理WebSocket断开连接"""
        # 将客户端从rule_updates组移除
        await self.channel_layer.group_discard(
            'rule_updates',
            self.channel_name
        )

    async def receive(self, text_data):
        """处理从WebSocket接收到的消息"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')

            if message_type == 'get_rules':
                # 获取规则
                rule_type = data.get('rule_type')
                filters = data.get('filters', {})

                if rule_type == 'info_collection':
                    rules = await self.get_info_collection_rules(filters)
                elif rule_type == 'vuln_scan':
                    rules = await self.get_vuln_scan_rules(filters)
                else:
                    # 不支持的规则类型
                    await self.send(text_data=json.dumps({
                        'type': 'error',
                        'message': '不支持的规则类型'
                    }))
                    return

                await self.send(text_data=json.dumps({
                    'type': 'rules',
                    'rule_type': rule_type,
                    'data': rules
                }))

            elif message_type == 'search_rules':
                # 搜索规则
                rule_type = data.get('rule_type')
                query = data.get('query', '')

                if rule_type == 'info_collection':
                    rules = await self.search_info_collection_rules(query)
                elif rule_type == 'vuln_scan':
                    rules = await self.search_vuln_scan_rules(query)
                else:
                    # 不支持的规则类型
                    await self.send(text_data=json.dumps({
                        'type': 'error',
                        'message': '不支持的规则类型'
                    }))
                    return

                await self.send(text_data=json.dumps({
                    'type': 'search_results',
                    'rule_type': rule_type,
                    'query': query,
                    'data': rules
                }))

        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': '无效的JSON数据'
            }))
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': str(e)
            }))

    async def rule_update(self, event):
        """处理规则更新事件"""
        # 转发规则更新通知给客户端
        await self.send(text_data=json.dumps({
            'type': 'rule_update',
            'action': event['action'],
            'rule_type': event['rule_type'],
            'rule_id': event['rule_id'],
            'data': event['data']
        }))

    async def send_current_rules(self):
        """发送当前所有规则"""
        # 获取信息收集规则
        info_collection_rules = await self.get_info_collection_rules({})

        # 发送信息收集规则
        await self.send(text_data=json.dumps({
            'type': 'rules',
            'rule_type': 'info_collection',
            'data': info_collection_rules
        }))

        # 获取漏洞检测规则
        vuln_scan_rules = await self.get_vuln_scan_rules({})

        # 发送漏洞检测规则
        await self.send(text_data=json.dumps({
            'type': 'rules',
            'rule_type': 'vuln_scan',
            'data': vuln_scan_rules
        }))

    @database_sync_to_async
    def get_info_collection_rules(self, filters):
        """获取信息收集规则"""
        queryset = InfoCollectionRule.objects.all()

        # 应用过滤器
        if 'module' in filters:
            queryset = queryset.filter(module=filters['module'])
        if 'scan_type' in filters:
            queryset = queryset.filter(scan_type=filters['scan_type'])
        if 'is_enabled' in filters:
            queryset = queryset.filter(is_enabled=filters['is_enabled'])

        # 序列化结果
        rules = []
        for rule in queryset:
            rules.append({
                'id': rule.id,
                'module': rule.module,
                'module_display': rule.get_module_display(),
                'scan_type': rule.scan_type,
                'scan_type_display': rule.get_scan_type_display(),
                'description': rule.description,
                'rule_type': rule.rule_type,
                'rule_type_display': rule.get_rule_type_display(),
                'match_values': rule.match_values,
                'behaviors': rule.behaviors,
                'is_enabled': rule.is_enabled,
                'created_at': rule.created_at.isoformat(),
                'updated_at': rule.updated_at.isoformat()
            })

        return rules

    @database_sync_to_async
    def get_vuln_scan_rules(self, filters):
        """获取漏洞检测规则"""
        queryset = VulnScanRule.objects.all()

        # 应用过滤器
        if 'vuln_type' in filters:
            queryset = queryset.filter(vuln_type=filters['vuln_type'])
        if 'scan_type' in filters:
            queryset = queryset.filter(scan_type=filters['scan_type'])
        if 'is_enabled' in filters:
            queryset = queryset.filter(is_enabled=filters['is_enabled'])

        # 序列化结果
        rules = []
        for rule in queryset:
            rules.append({
                'id': rule.id,
                'vuln_type': rule.vuln_type,
                'vuln_type_display': rule.get_vuln_type_display(),
                'scan_type': rule.scan_type,
                'scan_type_display': rule.get_scan_type_display(),
                'name': rule.name,
                'description': rule.description,
                'rule_content': rule.rule_content,
                'is_enabled': rule.is_enabled,
                'created_at': rule.created_at.isoformat(),
                'updated_at': rule.updated_at.isoformat()
            })

        return rules

    @database_sync_to_async
    def search_info_collection_rules(self, query):
        """搜索信息收集规则"""
        queryset = InfoCollectionRule.objects.filter(
            description__icontains=query
        ) | InfoCollectionRule.objects.filter(
            match_values__icontains=query
        ) | InfoCollectionRule.objects.filter(
            behaviors__icontains=query
        )

        # 序列化结果
        rules = []
        for rule in queryset:
            rules.append({
                'id': rule.id,
                'module': rule.module,
                'module_display': rule.get_module_display(),
                'scan_type': rule.scan_type,
                'scan_type_display': rule.get_scan_type_display(),
                'description': rule.description,
                'rule_type': rule.rule_type,
                'rule_type_display': rule.get_rule_type_display(),
                'match_values': rule.match_values,
                'behaviors': rule.behaviors,
                'is_enabled': rule.is_enabled,
                'created_at': rule.created_at.isoformat(),
                'updated_at': rule.updated_at.isoformat()
            })

        return rules

    @database_sync_to_async
    def search_vuln_scan_rules(self, query):
        """搜索漏洞检测规则"""
        queryset = VulnScanRule.objects.filter(
            name__icontains=query
        ) | VulnScanRule.objects.filter(
            description__icontains=query
        ) | VulnScanRule.objects.filter(
            rule_content__icontains=query
        )

        # 序列化结果
        rules = []
        for rule in queryset:
            rules.append({
                'id': rule.id,
                'vuln_type': rule.vuln_type,
                'vuln_type_display': rule.get_vuln_type_display(),
                'scan_type': rule.scan_type,
                'scan_type_display': rule.get_scan_type_display(),
                'name': rule.name,
                'description': rule.description,
                'rule_content': rule.rule_content,
                'is_enabled': rule.is_enabled,
                'created_at': rule.created_at.isoformat(),
                'updated_at': rule.updated_at.isoformat()
            })

        return rules