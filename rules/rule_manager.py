from django.utils import timezone
from .models import InfoCollectionRule, VulnScanRule


class RuleManager:
    """
    规则管理器：统一管理所有的规则
    """

    @staticmethod
    def create_info_collection_rule(module, scan_type, description, rule_type, match_values, behaviors=None):
        """
        创建信息收集规则

        参数:
            module: 模块 (network, os, component)
            scan_type: 扫描类型 (passive, active)
            description: 规则描述
            rule_type: 规则类型 (status_code, response_content, header)
            match_values: 匹配值（多行文本）
            behaviors: 行为（多行文本，主动扫描时使用）

        返回:
            创建的规则对象
        """
        rule = InfoCollectionRule.objects.create(
            module=module,
            scan_type=scan_type,
            description=description,
            rule_type=rule_type,
            match_values=match_values,
            behaviors=behaviors,
            is_enabled=True,
            created_at=timezone.now()
        )
        return rule

    @staticmethod
    def update_info_collection_rule(rule_id, **kwargs):
        """
        更新信息收集规则

        参数:
            rule_id: 规则ID
            kwargs: 要更新的字段

        返回:
            更新后的规则对象
        """
        rule = InfoCollectionRule.objects.get(id=rule_id)

        # 更新字段
        for field, value in kwargs.items():
            if hasattr(rule, field):
                setattr(rule, field, value)

        rule.save()
        return rule

    @staticmethod
    def delete_info_collection_rule(rule_id):
        """
        删除信息收集规则

        参数:
            rule_id: 规则ID
        """
        rule = InfoCollectionRule.objects.get(id=rule_id)
        rule.delete()

    @staticmethod
    def get_info_collection_rule(rule_id):
        """
        获取信息收集规则

        参数:
            rule_id: 规则ID

        返回:
            规则对象
        """
        return InfoCollectionRule.objects.get(id=rule_id)

    @staticmethod
    def get_info_collection_rules_by_module(module):
        """
        根据模块获取信息收集规则

        参数:
            module: 模块 (network, os, component)

        返回:
            规则对象列表
        """
        return InfoCollectionRule.objects.filter(module=module, is_enabled=True)

    @staticmethod
    def get_info_collection_rules_by_module_and_type(module, scan_type):
        """
        根据模块和扫描类型获取信息收集规则

        参数:
            module: 模块 (network, os, component)
            scan_type: 扫描类型 (passive, active)

        返回:
            规则对象列表
        """
        return InfoCollectionRule.objects.filter(module=module, scan_type=scan_type, is_enabled=True)

    @staticmethod
    def create_vuln_scan_rule(vuln_type, scan_type, name, description, rule_content):
        """
        创建漏洞检测规则

        参数:
            vuln_type: 漏洞类型
            scan_type: 扫描类型 (passive, active)
            name: 漏洞名称
            description: 漏洞描述
            rule_content: 规则内容

        返回:
            创建的规则对象
        """
        rule = VulnScanRule.objects.create(
            vuln_type=vuln_type,
            name=name,
            description=description,
            rule_content=rule_content,
            is_enabled=True,
            created_at=timezone.now()
        )
        return rule

    @staticmethod
    def update_vuln_scan_rule(rule_id, **kwargs):
        """
        更新漏洞检测规则

        参数:
            rule_id: 规则ID
            kwargs: 要更新的字段

        返回:
            更新后的规则对象
        """
        rule = VulnScanRule.objects.get(id=rule_id)

        # 更新字段
        for field, value in kwargs.items():
            if hasattr(rule, field):
                setattr(rule, field, value)

        rule.save()
        return rule

    @staticmethod
    def delete_vuln_scan_rule(rule_id):
        """
        删除漏洞检测规则

        参数:
            rule_id: 规则ID
        """
        rule = VulnScanRule.objects.get(id=rule_id)
        rule.delete()

    @staticmethod
    def get_vuln_scan_rule(rule_id):
        """
        获取漏洞检测规则

        参数:
            rule_id: 规则ID

        返回:
            规则对象
        """
        return VulnScanRule.objects.get(id=rule_id)

    @staticmethod
    def get_vuln_scan_rules_by_type(vuln_type):
        """
        根据漏洞类型获取漏洞检测规则

        参数:
            vuln_type: 漏洞类型

        返回:
            规则对象列表
        """
        return VulnScanRule.objects.filter(vuln_type=vuln_type, is_enabled=True)

    @staticmethod
    def get_vuln_scan_rules_by_type_and_scan_type(vuln_type, scan_type):
        """
        根据漏洞类型和扫描类型获取漏洞检测规则

        参数:
            vuln_type: 漏洞类型
            scan_type: 扫描类型 (passive, active)

        返回:
            规则对象列表
        """
        return VulnScanRule.objects.filter(vuln_type=vuln_type, scan_type=scan_type, is_enabled=True)

    @staticmethod
    def search_info_collection_rules(query):
        """
        搜索信息收集规则

        参数:
            query: 搜索关键词

        返回:
            规则对象列表
        """
        return InfoCollectionRule.objects.filter(
            description__icontains=query
        ) | InfoCollectionRule.objects.filter(
            match_values__icontains=query
        ) | InfoCollectionRule.objects.filter(
            behaviors__icontains=query
        )

    @staticmethod
    def search_vuln_scan_rules(query):
        """
        搜索漏洞检测规则

        参数:
            query: 搜索关键词

        返回:
            规则对象列表
        """
        return VulnScanRule.objects.filter(
            name__icontains=query
        ) | VulnScanRule.objects.filter(
            description__icontains=query
        ) | VulnScanRule.objects.filter(
            rule_content__icontains=query
        )