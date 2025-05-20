# vuln_scan/scanner.py
import asyncio
from urllib.parse import urlparse
from django.utils import timezone
from asgiref.sync import sync_to_async  # 只导入 sync_to_async，移除 database_sync_to_async
from data_collection.models import Asset
from .models import VulnScanResult

# 导入各个漏洞扫描模块
from .modules.sql_injection_scanner import SqlInjectionScanner
from .modules.xss_scanner import XssScanner
from .modules.file_inclusion_scanner import FileInclusionScanner
from .modules.rce_scanner import RceScanner
from .modules.ssrf_scanner import SsrfScanner  # 确保导入SSRF扫描器


class VulnScanner:
    """
    漏洞扫描器：负责进行漏洞扫描检测
    整合了多种漏洞类型的扫描模块
    """

    def __init__(self):
        """初始化扫描器"""
        self.is_scanning = False
        self.use_proxy = False
        self.proxy_address = "http://localhost:7890"
        self.scan_timeout = 30  # 默认扫描超时时间（秒）
        self.max_concurrent_scans = 5  # 默认最大并发扫描数
        self.skip_targets = set()  # 要跳过的目标集合
        self.semaphore = asyncio.Semaphore(2)  # 默认并发数控制

        # 初始化各个漏洞扫描模块
        self.sql_injection_scanner = SqlInjectionScanner()
        self.xss_scanner = XssScanner()
        self.file_inclusion_scanner = FileInclusionScanner()

        # 特殊初始化RCE扫描器和SSRF扫描器
        self.rce_scanner = self._init_rce_scanner()
        self.ssrf_scanner = self._init_ssrf_scanner()  # 使用特殊的初始化方法

        # 已扫描的URL记录
        self.scanned_urls = set()

    def _init_rce_scanner(self):
        """初始化RCE扫描器，处理可能的导入错误"""
        try:
            print("============= 开始初始化RCE扫描器... =============")
            # 清晰的初始化日志

            # 验证类是否成功导入
            try:
                rce_scanner_type = type(RceScanner)
                print(f"RCE扫描器类型: {rce_scanner_type}")
            except Exception as type_err:
                print(f"获取RCE扫描器类型失败: {str(type_err)}")
                import traceback
                traceback.print_exc()

            # 创建扫描器实例
            rce_scanner = RceScanner()
            print(f"RCE扫描器实例创建成功: {rce_scanner}")

            # 检查关键方法
            has_load_method = hasattr(rce_scanner, 'load_payloads')
            has_scan_method = hasattr(rce_scanner, 'scan')
            print(f"RCE扫描器方法检查 - load_payloads: {has_load_method}, scan: {has_scan_method}")

            # 异步加载规则
            if has_load_method:
                try:
                    # 创建异步任务并记录结果
                    task = asyncio.create_task(rce_scanner.load_payloads())

                    def log_result(future):
                        try:
                            result = future.result()
                            print(f"RCE规则加载结果: {result}")
                        except Exception as future_err:
                            print(f"RCE规则加载异步任务出错: {str(future_err)}")
                            import traceback
                            traceback.print_exc()

                    task.add_done_callback(log_result)
                    print("RCE规则加载任务已创建")
                except Exception as load_err:
                    print(f"创建RCE规则加载任务失败: {str(load_err)}")
                    import traceback
                    traceback.print_exc()
            else:
                print("警告: RCE扫描器没有load_payloads方法")

            print("============= RCE扫描器初始化成功 =============")
            return rce_scanner
        except ImportError as e:
            print(f"导入RCE扫描器模块失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
        except Exception as e:
            print(f"RCE扫描器初始化失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def _init_ssrf_scanner(self):
        """初始化SSRF扫描器，处理可能的导入错误"""
        try:
            print("===== 开始初始化SSRF扫描器... =====")

            # 首先验证类是否可以导入
            try:
                ssrf_scanner_type = type(SsrfScanner)
                print(f"SSRF扫描器类型: {ssrf_scanner_type}")
            except Exception as type_err:
                print(f"获取SSRF扫描器类型失败: {str(type_err)}")

            # 创建扫描器实例
            ssrf_scanner = SsrfScanner()
            print(f"SSRF扫描器实例创建成功: {ssrf_scanner}")

            # 检查关键方法
            has_load_method = hasattr(ssrf_scanner, 'load_payloads')
            has_scan_method = hasattr(ssrf_scanner, 'scan')
            print(f"SSRF扫描器方法检查 - load_payloads: {has_load_method}, scan: {has_scan_method}")

            # 同步加载规则以确保初始化成功
            if has_load_method:
                try:
                    # 创建异步任务并设置回调函数记录结果
                    task = asyncio.create_task(ssrf_scanner.load_payloads())

                    def log_result(future):
                        try:
                            result = future.result()
                            print(f"SSRF规则加载结果: {result}")
                        except Exception as future_err:
                            print(f"SSRF规则加载异步任务出错: {str(future_err)}")
                            import traceback
                            traceback.print_exc()

                    task.add_done_callback(log_result)
                    print("SSRF规则加载任务已创建")
                except Exception as load_err:
                    print(f"创建SSRF规则加载任务失败: {str(load_err)}")
                    import traceback
                    traceback.print_exc()
            else:
                print("警告: SSRF扫描器没有load_payloads方法")

            print("===== SSRF扫描器初始化成功 =====")
            return ssrf_scanner

        except ImportError as e:
            print(f"导入SSRF扫描器模块失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
        except Exception as e:
            print(f"SSRF扫描器初始化失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def reset_scan_state(self):
        """重置扫描状态，清除缓存"""
        self.scanned_urls.clear()

        # 重置各个扫描模块的缓存
        if hasattr(self.sql_injection_scanner, 'clear_cache'):
            self.sql_injection_scanner.clear_cache()

        if hasattr(self.xss_scanner, 'clear_cache'):
            self.xss_scanner.clear_cache()

        if hasattr(self.file_inclusion_scanner, 'clear_cache'):
            self.file_inclusion_scanner.clear_cache()

        if self.ssrf_scanner and hasattr(self.ssrf_scanner, 'clear_cache'):  # 检查SSRF扫描器是否初始化
            try:
                self.ssrf_scanner.clear_cache()
                print("SSRF扫描器缓存已清除")
            except Exception as e:
                print(f"清除SSRF扫描器缓存失败: {str(e)}")

        if self.rce_scanner and hasattr(self.rce_scanner, 'clear_cache'):
            try:
                self.rce_scanner.clear_cache()
                print("RCE扫描器缓存已清除")
            except Exception as e:
                print(f"清除RCE扫描器缓存失败: {str(e)}")

        print("漏洞扫描器状态已重置")

    async def scan_data(self, channel_layer, asset_id, url, method, status_code, req_headers, req_content, resp_headers,
                        resp_content):
        """
        扫描数据

        参数:
            channel_layer: 通道层
            asset_id: 资产ID
            url: URL
            method: HTTP方法
            status_code: 响应状态码
            req_headers: 请求头
            req_content: 请求内容
            resp_headers: 响应头
            resp_content: 响应内容
        """
        print(f"\n==================== 开始扫描数据 URL={url} ====================")

        # 解析URL获取主机名
        parsed_url = urlparse(url)
        host = parsed_url.netloc

        # 检查是否需要跳过此目标
        if host in self.skip_targets:
            print(f"跳过目标: {host} (在跳过列表中)")
            return

        # 检查URL是否已扫描
        if url in self.scanned_urls:
            print(f"跳过已扫描URL: {url}")
            return

        # 标记URL为已扫描
        self.scanned_urls.add(url)

        # 获取资产
        asset = await self.get_asset(asset_id)
        if not asset:
            print(f"无法获取资产信息，资产ID: {asset_id}")
            return

        # 使用信号量控制并发扫描数量
        async with self.semaphore:
            # 设置信号量大小
            self.semaphore._value = self.max_concurrent_scans

            # 进行扫描
            try:
                # 创建扫描上下文
                context = {
                    'asset': asset,
                    'url': url,
                    'method': method,
                    'status_code': status_code,
                    'req_headers': req_headers,
                    'req_content': req_content,
                    'resp_headers': resp_headers,
                    'resp_content': resp_content,
                    'channel_layer': channel_layer,
                    'use_proxy': self.use_proxy,
                    'proxy_address': self.proxy_address,
                    'scan_timeout': self.scan_timeout
                }

                # 发送扫描开始事件
                await channel_layer.group_send(
                    'vuln_scan_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'scanning',
                            'message': f'正在扫描 {host}',
                            'url': url,
                            'progress': 0
                        }
                    }
                )

                # 创建任务列表
                tasks = []

                # 添加SQL注入扫描任务
                tasks.append(self.sql_injection_scanner.scan(context))
                print("添加SQL注入扫描任务")

                # 添加XSS扫描任务
                tasks.append(self.xss_scanner.scan(context))
                print("添加XSS扫描任务")

                # 添加文件包含扫描任务
                tasks.append(self.file_inclusion_scanner.scan(context))
                print("添加文件包含扫描任务")

                # 添加SSRF扫描任务，增加错误处理
                if self.ssrf_scanner:  # 检查SSRF扫描器是否成功初始化
                    try:
                        # 检查SSRF扫描器scan方法是否可用
                        if hasattr(self.ssrf_scanner, 'scan'):
                            print(f"尝试添加SSRF扫描任务: {url}")
                            # 首先验证scan方法是否可调用
                            if callable(getattr(self.ssrf_scanner, 'scan')):
                                tasks.append(self.ssrf_scanner.scan(context))
                                print(f"成功添加SSRF扫描任务: {url}")
                            else:
                                print("SSRF扫描器scan方法不可调用，跳过")
                        else:
                            print("SSRF扫描器没有scan方法，跳过")
                    except Exception as e:
                        print(f"添加SSRF扫描任务时出错: {str(e)}")
                        import traceback
                        traceback.print_exc()
                else:
                    print("SSRF扫描器未初始化，跳过SSRF扫描")

                # 添加RCE扫描任务，增加错误处理
                if self.rce_scanner:  # 检查RCE扫描器是否成功初始化
                    try:
                        # 详细检查RCE扫描器状态
                        print(f"RCE扫描器对象: {self.rce_scanner}")
                        print(f"RCE扫描器类型: {type(self.rce_scanner)}")
                        print(f"RCE扫描器是否有scan方法: {hasattr(self.rce_scanner, 'scan')}")
                        print(f"RCE扫描器规则是否已加载: {getattr(self.rce_scanner, 'rules_loaded', False)}")
                        print(f"RCE载荷数量: {len(getattr(self.rce_scanner, 'rce_payloads', []))}")
                        print(f"RCE匹配模式数量: {len(getattr(self.rce_scanner, 'match_patterns', []))}")

                        # 检查RCE扫描器scan方法是否可用
                        if hasattr(self.rce_scanner, 'scan'):
                            print(f"尝试添加RCE扫描任务: {url}")
                            # 首先验证scan方法是否可调用
                            if callable(getattr(self.rce_scanner, 'scan')):
                                tasks.append(self.rce_scanner.scan(context))
                                print(f"成功添加RCE扫描任务: {url}")
                            else:
                                print("RCE扫描器scan方法不可调用，跳过")
                        else:
                            print("RCE扫描器没有scan方法，跳过")
                    except Exception as e:
                        print(f"添加RCE扫描任务时出错: {str(e)}")
                        import traceback
                        traceback.print_exc()
                else:
                    print("RCE扫描器未初始化，跳过RCE扫描")

                print(f"创建了 {len(tasks)} 个扫描任务")

                # 等待所有任务完成或有一个失败，增加错误处理
                scan_results = []
                for i, task in enumerate(tasks):
                    try:
                        result = await task
                        scan_results.append(result)
                        scanner_name = ["SQL注入", "XSS", "文件包含", "SSRF", "RCE"][min(i, 4)]
                        print(f"{scanner_name}扫描完成，结果数量: {len(result) if result else 0}")
                    except Exception as e:
                        scanner_name = ["SQL注入", "XSS", "文件包含", "SSRF", "RCE"][min(i, 4)]
                        print(f"{scanner_name}扫描出错: {str(e)}")
                        import traceback
                        traceback.print_exc()
                        scan_results.append([])  # 添加空列表保持索引一致

                # 处理扫描结果
                vuln_results = []

                # 合并所有有效的扫描结果
                for i, result in enumerate(scan_results):
                    if result:  # 如果结果不为空或None
                        scanner_name = ["SQL注入", "XSS", "文件包含", "SSRF", "RCE"][min(i, 4)]
                        print(f"合并{scanner_name}扫描结果: {len(result)}个")
                        vuln_results.extend(result)

                # 保存漏洞结果
                print(f"共发现 {len(vuln_results)} 个漏洞")
                for result in vuln_results:
                    vuln_result = await self.save_vuln_result(
                        asset=asset,
                        vuln_type=result['vuln_type'],
                        vuln_subtype=result.get('vuln_subtype'),
                        name=result['name'],
                        description=result['description'],
                        severity=result['severity'],
                        url=result['url'],
                        request=result.get('request'),
                        response=result.get('response'),
                        proof=result.get('proof'),
                        parameter=result.get('parameter'),
                        payload=result.get('payload')
                    )

                    # 发送漏洞结果事件
                    if vuln_result:
                        await channel_layer.group_send(
                            'vuln_scan_scanner',
                            {
                                'type': 'scan_result',
                                'data': {
                                    'id': vuln_result.id,
                                    'asset': asset.host,
                                    'vuln_type': vuln_result.vuln_type,
                                    'vuln_type_display': vuln_result.get_vuln_type_display(),
                                    'vuln_subtype': vuln_result.vuln_subtype,
                                    'name': vuln_result.name,
                                    'description': vuln_result.description,
                                    'severity': vuln_result.severity,
                                    'severity_display': vuln_result.get_severity_display(),
                                    'url': vuln_result.url,
                                    'request': vuln_result.request,
                                    'response': vuln_result.response,
                                    'proof': vuln_result.proof,
                                    'scan_date': vuln_result.scan_date.isoformat(),
                                    'is_verified': vuln_result.is_verified,
                                    'parameter': vuln_result.parameter,
                                    'payload': vuln_result.payload
                                }
                            }
                        )

                # 发送扫描完成事件
                await channel_layer.group_send(
                    'vuln_scan_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'completed',
                            'message': f'扫描完成: {host}, 发现 {len(vuln_results)} 个漏洞',
                            'url': url,
                            'progress': 100
                        }
                    }
                )

                print(f"==================== 扫描完成 URL={url} ====================\n")

            except Exception as e:
                print(f"扫描过程中发生错误: {str(e)}")
                import traceback
                traceback.print_exc()

                # 发送扫描错误事件
                await channel_layer.group_send(
                    'vuln_scan_scanner',
                    {
                        'type': 'scan_progress',
                        'data': {
                            'status': 'error',
                            'message': f'扫描错误: {str(e)}',
                            'url': url,
                            'progress': 0
                        }
                    }
                )

    # 辅助方法

    @sync_to_async
    def get_asset(self, asset_id):
        """获取资产"""
        try:
            return Asset.objects.get(id=asset_id)
        except Asset.DoesNotExist:
            print(f"资产不存在，ID: {asset_id}")
            return None
        except Exception as e:
            print(f"获取资产失败: {str(e)}")
            return None

    async def save_vuln_result(self, asset, vuln_type, vuln_subtype, name, description, severity, url, request,
                               response, proof, parameter=None, payload=None):
        """保存漏洞结果，增加去重逻辑"""
        try:
            # 生成唯一Key用于查重
            unique_key = f"{vuln_type}-{vuln_subtype}-{parameter}-{url}"

            # 检查是否已存在相同的漏洞结果
            existing_results = await self._get_existing_results(asset.id, vuln_type, vuln_subtype, url, name)

            # 如果不存在相同的结果，才创建新记录
            if not existing_results:
                # 创建新的漏洞记录
                result = await self._create_vuln_result(
                    asset=asset,
                    vuln_type=vuln_type,
                    vuln_subtype=vuln_subtype,
                    name=name,
                    description=description,
                    severity=severity,
                    url=url,
                    request=request,
                    response=response,
                    proof=proof,
                    parameter=parameter,
                    payload=payload
                )

                # 返回新创建的记录
                return result
            else:
                # 如果已存在，记录日志并返回已存在的记录
                print(f"发现重复漏洞: {unique_key}，跳过")
                return existing_results[0]
        except Exception as e:
            # 如果保存失败，记录错误
            print(f"保存漏洞结果失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    @sync_to_async  # 将 database_sync_to_async 改为 sync_to_async
    def _get_existing_results(self, asset_id, vuln_type, vuln_subtype, url, name):
        """查询是否存在相同的漏洞结果"""
        from vuln_scan.models import VulnScanResult

        try:
            # 构建查询条件
            query_kwargs = {
                'asset_id': asset_id,
                'vuln_type': vuln_type,
                'url': url,
            }

            # 如果有子类型，添加到查询条件
            if vuln_subtype:
                query_kwargs['vuln_subtype'] = vuln_subtype

            # 查询数据库
            results = list(VulnScanResult.objects.filter(**query_kwargs)[:1])

            return results
        except Exception as e:
            print(f"查询已存在漏洞时出错: {str(e)}")
            return []

    @sync_to_async  # 将 database_sync_to_async 改为 sync_to_async
    def _create_vuln_result(self, asset, vuln_type, vuln_subtype, name, description, severity, url, request,
                            response, proof, parameter, payload):
        """创建新的漏洞记录"""
        from vuln_scan.models import VulnScanResult

        return VulnScanResult.objects.create(
            asset=asset,
            vuln_type=vuln_type,
            vuln_subtype=vuln_subtype,
            name=name,
            description=description,
            severity=severity,
            url=url,
            request=request,
            response=response,
            proof=proof,
            parameter=parameter,
            payload=payload,
            scan_date=timezone.now()
        )