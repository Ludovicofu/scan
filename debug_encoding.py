#!/usr/bin/env python
import os
import sys
import json
import re
import argparse
from collections import defaultdict, Counter

# 定义要检查的关键文件路径
key_files = {
    'data_collection_consumer': 'data_collection/consumers.py',
    'vuln_scan_consumer': 'vuln_scan/consumers.py',
    'data_collection_scanner': 'data_collection/scanner.py',
    'network_scanner': 'data_collection/modules/network_scanner.py',
    'os_scanner': 'data_collection/modules/os_scanner.py',
    'component_scanner': 'data_collection/modules/component_scanner.py',
    'vuln_scanner': 'vuln_scan/scanner.py',
    'sql_injection_scanner': 'vuln_scan/modules/sql_injection_scanner.py',
}

# 缓存机制关键词
cache_patterns = {
    'cache_definition': r'(?:self|_)\.(?:\w+_)?(?:cache|scanned|found|result)(?:_\w+)?\s*=\s*(?:set|dict|{}|\[\])\(\)',
    'cache_check': r'(?:if|while).*?in\s+(?:self|_)\.(?:\w+_)?(?:cache|scanned|found|result)',
    'cache_add': r'(?:self|_)\.(?:\w+_)?(?:cache|scanned|found|result)(?:_\w+)?\.(?:add|append)',
    'result_send': r'(?:send|group_send).*?\'(?:type|scan).*?result',
    'deduplication': r'(?:existing|is_result_in_cache|check_existing|already|duplicate|skip)',
}

# 扫描结果处理关键词
result_patterns = {
    'result_creation': r'(?:create|save).*?(?:result|scan_result)',
    'result_check': r'check_existing_result',
}


def parse_file(file_path, patterns):
    """分析文件中的匹配模式"""
    if not os.path.exists(file_path):
        return {pattern: [] for pattern in patterns}

    results = {pattern: [] for pattern in patterns}

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            line_num = 1
            for line in content.split('\n'):
                for pattern_name, pattern in patterns.items():
                    if re.search(pattern, line):
                        results[pattern_name].append((line_num, line.strip()))
                line_num += 1
    except Exception as e:
        print(f"Error parsing {file_path}: {str(e)}")

    return results


def check_scan_result_function(file_path):
    """检查scan_result函数中的去重逻辑"""
    if not os.path.exists(file_path):
        return {}

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # 查找定义了scan_result函数的区域
            scan_result_function = re.search(r'async\s+def\s+scan_result\s*\([^)]*\):(.*?)(?:async\s+def|\Z)', content,
                                             re.DOTALL)

            if not scan_result_function:
                return {"has_scan_result": False}

            function_body = scan_result_function.group(1)

            # 检查函数中是否有去重逻辑
            has_cache_check = bool(
                re.search(r'(?:if|while).*?in\s+(?:self|_)\.(?:\w+_)?(?:cache|scanned|found|result)', function_body))
            has_cache_add = bool(
                re.search(r'(?:self|_)\.(?:\w+_)?(?:cache|scanned|found|result)(?:_\w+)?\.(?:add|append)',
                          function_body))
            has_skip_logic = bool(re.search(r'(?:return|continue|break).*?(?:duplicate|skip|already)', function_body))

            return {
                "has_scan_result": True,
                "has_cache_check": has_cache_check,
                "has_cache_add": has_cache_add,
                "has_skip_logic": has_skip_logic,
                "function_body": function_body
            }
    except Exception as e:
        print(f"Error analyzing scan_result in {file_path}: {str(e)}")
        return {"has_scan_result": False, "error": str(e)}


def analyze_module_cache_mechanisms(base_path):
    """分析各模块的缓存机制"""
    results = {}

    for module_name, file_path in key_files.items():
        full_path = os.path.join(base_path, file_path)

        # 分析缓存模式
        cache_results = parse_file(full_path, cache_patterns)

        # 分析结果处理模式
        result_handling = parse_file(full_path, result_patterns)

        # 特别检查scan_result函数
        scan_result_analysis = {}
        if module_name.endswith('consumer'):
            scan_result_analysis = check_scan_result_function(full_path)

        results[module_name] = {
            "file_path": file_path,
            "cache_mechanisms": cache_results,
            "result_handling": result_handling,
            "scan_result_analysis": scan_result_analysis
        }

        # 检查缓存清理方法
        if os.path.exists(full_path):
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
                has_clear_cache = bool(re.search(r'def\s+clear_cache', content))
                results[module_name]["has_clear_cache"] = has_clear_cache

    return results


def check_duplicate_issue_locations(analysis_results):
    """根据分析结果确定可能的重复问题位置"""
    potential_issues = []

    # 检查消费者的scan_result函数
    for module_name, results in analysis_results.items():
        if module_name.endswith('consumer'):
            scan_result = results.get('scan_result_analysis', {})

            if scan_result.get('has_scan_result', False):
                if not scan_result.get('has_cache_check', False):
                    potential_issues.append({
                        "module": module_name,
                        "issue": "scan_result函数缺少缓存检查",
                        "severity": "高",
                        "suggestion": "在发送结果前添加重复检查逻辑"
                    })
                elif not scan_result.get('has_skip_logic', False):
                    potential_issues.append({
                        "module": module_name,
                        "issue": "scan_result函数缺少跳过重复结果的逻辑",
                        "severity": "中",
                        "suggestion": "添加检测到重复后跳过的逻辑"
                    })

    # 检查各扫描器模块的缓存机制
    for module_name, results in analysis_results.items():
        if not module_name.endswith('consumer') and not module_name.endswith('scanner'):
            # 检查是否有缓存定义
            cache_definitions = results['cache_mechanisms'].get('cache_definition', [])
            if not cache_definitions:
                potential_issues.append({
                    "module": module_name,
                    "issue": "模块没有定义缓存机制",
                    "severity": "中",
                    "suggestion": "添加结果缓存以避免重复"
                })

            # 检查是否有缓存清理方法
            if not results.get('has_clear_cache', False):
                potential_issues.append({
                    "module": module_name,
                    "issue": "缺少缓存清理方法",
                    "severity": "低",
                    "suggestion": "添加clear_cache方法以便重置状态"
                })

    return potential_issues


def generate_report(analysis_results, potential_issues):
    """生成分析报告"""
    report = {
        "summary": {
            "total_modules_analyzed": len(analysis_results),
            "potential_issues_found": len(potential_issues),
            "modules_with_issues": len(set(issue["module"] for issue in potential_issues))
        },
        "detailed_issues": potential_issues,
        "module_analysis": analysis_results
    }

    # 分析问题模块的分布
    issue_by_type = Counter()
    issue_by_module = Counter()

    for issue in potential_issues:
        issue_by_type[issue["issue"]] += 1
        issue_by_module[issue["module"]] += 1

    report["issue_distribution"] = {
        "by_type": dict(issue_by_type),
        "by_module": dict(issue_by_module)
    }

    # 确定主要问题区域
    if issue_by_module:
        most_problematic_module = issue_by_module.most_common(1)[0][0]
        report["conclusion"] = {
            "most_problematic_module": most_problematic_module,
            "primary_issue_area": "信息收集模块" if "data_collection" in most_problematic_module else "漏洞扫描模块",
            "recommendation": "首先检查 " + most_problematic_module + " 模块的缓存和去重逻辑"
        }
    else:
        report["conclusion"] = {
            "note": "未发现明显的问题区域"
        }

    return report


def main():
    parser = argparse.ArgumentParser(description='分析扫描系统的缓存机制和重复问题')
    parser.add_argument('--path', type=str, default='.', help='代码根目录路径')
    parser.add_argument('--output', type=str, default='cache_analysis_report.json', help='输出报告文件名')

    args = parser.parse_args()

    # 分析各模块的缓存机制
    analysis_results = analyze_module_cache_mechanisms(args.path)

    # 检查可能的重复问题位置
    potential_issues = check_duplicate_issue_locations(analysis_results)

    # 生成报告
    report = generate_report(analysis_results, potential_issues)

    # 输出报告
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # 打印结论
    print("\n===== 分析结论 =====")
    if "conclusion" in report and "primary_issue_area" in report["conclusion"]:
        print(f"主要问题区域: {report['conclusion']['primary_issue_area']}")
        print(f"最有问题的模块: {report['conclusion']['most_problematic_module']}")
        print(f"建议: {report['conclusion']['recommendation']}")
    else:
        print("未发现明显的问题区域")

    print(f"\n详细报告已保存到 {args.output}")
    print(f"发现的潜在问题数量: {len(potential_issues)}")


if __name__ == "__main__":
    main()