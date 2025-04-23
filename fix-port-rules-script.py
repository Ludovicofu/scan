#!/usr/bin/env python
"""
端口扫描规则修复脚本（MySQL版本）

这个脚本用于检查和修复端口扫描规则配置问题。
它会检查数据库中是否存在端口扫描规则，如果不存在则创建默认规则。
"""

import os
import sys
import django

# 设置Django环境
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "system.settings")
django.setup()

from django.utils import timezone
from rules.models import InfoCollectionRule
from django.db import connection
from django.db.models import Q


def check_port_rule_type():
    """检查InfoCollectionRule模型是否支持port规则类型"""
    # 获取InfoCollectionRule模型中rule_type字段的选项
    rule_type_choices = dict(InfoCollectionRule.RULE_TYPE_CHOICES)
    print(f"规则类型选项: {rule_type_choices}")

    # 检查是否包含'port'选项
    has_port_type = 'port' in rule_type_choices
    if has_port_type:
        print("✅ InfoCollectionRule模型支持端口(port)规则类型")
    else:
        print("❌ InfoCollectionRule模型不支持端口(port)规则类型")
        print("请检查迁移文件'rules/migrations/0002_add_port_rule_type.py'是否已应用")

    return has_port_type


def check_table_schema():
    """检查数据库表结构（MySQL版本）"""
    try:
        with connection.cursor() as cursor:
            # 获取表信息（MySQL语法）
            cursor.execute("DESCRIBE rules_infocollectionrule;")
            columns = cursor.fetchall()
            print("\n数据库表结构:")
            for column in columns:
                print(f"列: {column}")

            # 检查表创建语句
            cursor.execute("SHOW CREATE TABLE rules_infocollectionrule;")
            table_def = cursor.fetchone()
            if table_def and len(table_def) > 1:
                print(f"\n表定义: {table_def[1]}")
    except Exception as e:
        print(f"❌ 无法检查表结构: {str(e)}")
        print("继续执行其他检查...")


def get_port_scan_rules():
    """获取所有端口扫描规则"""
    port_rules = InfoCollectionRule.objects.filter(
        module='network',
        rule_type='port',
        scan_type='active'
    )

    print(f"\n找到 {port_rules.count()} 个端口扫描规则:")
    for rule in port_rules:
        print(f"  规则ID: {rule.id}")
        print(f"  描述: {rule.description}")
        print(f"  匹配值: {rule.match_values}")
        print(f"  启用状态: {'启用' if rule.is_enabled else '禁用'}")
        print()

    return port_rules


def create_default_port_rule():
    """创建默认端口扫描规则"""
    default_ports = '80\n443\n8080\n3306\n22\n21'

    print(f"\n创建默认端口扫描规则...")
    try:
        port_rule = InfoCollectionRule.objects.create(
            module='network',
            scan_type='active',
            description='端口扫描',
            rule_type='port',
            match_values=default_ports,
            behaviors='',
            is_enabled=True,
            created_at=timezone.now()
        )
        print(f"✅ 成功创建默认端口扫描规则 (ID: {port_rule.id})")
        return True
    except Exception as e:
        print(f"❌ 创建默认端口扫描规则失败: {str(e)}")
        return False


def check_all_rules():
    """检查数据库中的所有规则"""
    all_rules = InfoCollectionRule.objects.all()

    print(f"\n数据库中共有 {all_rules.count()} 条规则:")

    # 按模块分组统计
    module_stats = {}
    for rule in all_rules:
        module = rule.get_module_display()
        if module not in module_stats:
            module_stats[module] = 0
        module_stats[module] += 1

    for module, count in module_stats.items():
        print(f"  {module}: {count}条")

    # 按规则类型分组统计
    type_stats = {}
    for rule in all_rules:
        rule_type = rule.get_rule_type_display()
        if rule_type not in type_stats:
            type_stats[rule_type] = 0
        type_stats[rule_type] += 1

    print("\n规则类型统计:")
    for rule_type, count in type_stats.items():
        print(f"  {rule_type}: {count}条")


def fix_port_rules():
    """修复端口扫描规则问题"""
    # 检查模型是否支持port规则类型
    has_port_type = check_port_rule_type()
    if not has_port_type:
        print("需要先修复InfoCollectionRule模型")
        return

    # 检查表结构
    check_table_schema()

    # 检查所有规则
    check_all_rules()

    # 获取端口扫描规则
    port_rules = get_port_scan_rules()

    # 如果没有端口扫描规则，创建一个
    if not port_rules.exists():
        create_default_port_rule()
    else:
        # 如果有，检查是否至少有一个启用的规则
        enabled_rules = port_rules.filter(is_enabled=True)
        if not enabled_rules.exists():
            print("\n没有启用的端口扫描规则，启用第一个规则...")
            port_rules.first().is_enabled = True
            port_rules.first().save()
            print(f"✅ 成功启用规则 (ID: {port_rules.first().id})")


if __name__ == "__main__":
    print("开始修复端口扫描规则...")
    fix_port_rules()
    print("\n修复完成！")