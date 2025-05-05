"""
网络信息扫描模块：负责扫描网络相关信息
增强版: 加强了去重逻辑，防止数据库唯一性约束错误
"""
import asyncio
import time
from urllib.parse import urlparse, urljoin
from ..network_info import NetworkInfoScanner


class NetworkScanner:
    """网络信息扫描模块类 - 增强去重功能"""

    def __init__(self):
        """初始化扫描器"""
        self.network_info_scanner = NetworkInfoScanner()

        # 增强缓存结构
        # 格式: "(asset_id)-(module)-(description)-(rule_type)"
        self.result_cache = set()

        # 为每个资产的端口扫描添加时间戳记录
        # 格式: {(asset_id, 'port'): timestamp}
        self.port_scan_timestamps = {}

        # 端口扫描最小间隔(秒)
        self.port_scan_interval = 3600  # 默认1小时

        # 添加全局锁，防止并发写入
        self.scan_lock = asyncio.Lock()

    def clear_cache(self):
        """清除缓存"""
        self.result_cache.clear()
        self.port_scan_timestamps.clear()
        print("网络扫描器缓存已清除")

        # 如果 NetworkInfoScanner 也有缓存清理方法，同时清理
        if hasattr(self.network_info_scanner, 'clear_cache'):
            self.network_info_scanner.clear_cache()

    def get_cache_key(self, asset_id, module, description, rule_type):
        """
        生成统一格式的缓存键

        参数:
            asset_id: 资产ID
            module: 模块名称
            description: 描述
            rule_type: 规则类型

        返回:
            缓存键字符串
        """
        return f"{asset_id}-{module}-{description}-{rule_type}"

    async def scan(self, context):
        """
        扫描网络信息

        参数:
            context: 扫描上下文
        """
        # 获取上下文数据
        asset = context['asset']
        url = context['url']
        channel_layer = context['channel_layer']
        helpers = context['helpers']
        use_proxy = context['use_proxy']
        proxy_address = context['proxy_address']
        scan_timeout = context['scan_timeout']

        # 获取全局扫描器实例
        scanner = context.get('scanner')

        # 使用网络信息扫描器进行主动扫描
        active_rules = await helpers.get_rules('network', 'active')
        print(f"获取到 {len(active_rules)} 条网络模块主动扫描规则")

        # 打印规则详情用于调试
        for rule in active_rules:
            print(f"规则ID: {rule['id']}, 描述: {rule['description']}, 规则类型: {rule['rule_type']}")
            print(f"行为列表: {rule['behaviors']}")
            print(f"匹配值列表: {rule['match_values']}")
            print("-" * 50)

        # 进行主动扫描
        await self._do_active_scan(
            active_rules=active_rules,
            context=context,
            helpers=helpers,
            scanner=scanner
        )

    async def _do_active_scan(self, active_rules, context, helpers, scanner=None):
        """执行主动扫描，增强去重逻辑"""
        asset = context['asset']
        url = context['url']
        channel_layer = context['channel_layer']
        use_proxy = context['use_proxy']
        proxy_address = context['proxy_address']
        scan_timeout = context['scan_timeout']

        # 遍历主动扫描规则
        for rule in active_rules:
            rule_id = rule['id']
            description = rule['description']
            rule_type = rule['rule_type']
            match_values = rule['match_values']
            behaviors = rule['behaviors']

            # 创建缓存键
            cache_key = self.get_cache_key(asset.id, 'network', description, rule_type)

            # 对端口扫描规则的特殊处理
            if rule_type == 'port':
                # 为每个资产的端口扫描创建唯一键
                port_scan_key = (asset.id, 'port')

                # 获取当前时间戳
                current_time = time.time()

                # 检查是否在规定时间间隔内已经扫描过
                last_scan_time = self.port_scan_timestamps.get(port_scan_key, 0)
                time_diff = current_time - last_scan_time

                if time_diff < self.port_scan_interval:
                    print(f"跳过端口扫描，资产 {asset.host} 在 {time_diff:.2f} 秒前已扫描 (最小间隔: {self.port_scan_interval} 秒)")
                    continue

                try:
                    # 解析URL获取主机名
                    parsed_url = urlparse(url)
                    host = parsed_url.netloc

                    # 处理带端口号的主机名
                    if ':' in host:
                        host = host.split(':')[0]

                    print(f"准备对主机 {host} 进行端口扫描, 端口列表: {match_values}")

                    # 设置超时
                    scan_result = await asyncio.wait_for(
                        self.network_info_scanner.scan(
                            url=url,
                            behavior='',  # 端口扫描不需要行为
                            rule_type='port',
                            match_values=match_values,
                            use_proxy=use_proxy,
                            proxy_address=proxy_address
                        ),
                        timeout=scan_timeout
                    )

                    # 如果有匹配结果，保存扫描结果
                    if scan_result:
                        match_value = scan_result.get('match_value', '')
                        print(f"端口扫描有结果: {match_value}")

                        # 构建端口扫描的请求和响应数据
                        port_request_data = f"PORT SCAN {host}\nPorts: {', '.join(match_values)}"
                        port_response_data = f"Open ports: {match_value}"

                        # 使用异步锁保护数据库操作
                        async with self.scan_lock:
                            # 二次检查数据库是否已存在相同结果
                            existing = await helpers.check_existing_result(
                                asset=asset,
                                module='network',
                                description=description,
                                rule_type=rule_type,
                                match_value=match_value
                            )

                            # 检查全局缓存
                            global_cache_hit = False
                            if scanner and hasattr(scanner, 'is_result_in_cache') and scanner.is_result_in_cache(
                                    asset.id, 'network', description, rule_type, match_value):
                                global_cache_hit = True
                                print(f"全局缓存命中: {cache_key}")

                            # 检查模块级缓存
                            local_cache_hit = cache_key in self.result_cache
                            if local_cache_hit:
                                print(f"本地缓存命中: {cache_key}")

                            # 如果缓存命中或数据库已存在，跳过
                            if global_cache_hit or local_cache_hit or existing:
                                print(f"跳过重复的端口扫描结果: 资产={asset.host}, 描述={description}")

                                # 即使跳过，也更新时间戳
                                self.port_scan_timestamps[port_scan_key] = current_time
                                continue

                            # 添加到模块级缓存
                            self.result_cache.add(cache_key)

                            # 更新端口扫描时间戳
                            self.port_scan_timestamps[port_scan_key] = current_time

                            # 添加到全局缓存
                            if scanner and hasattr(scanner, 'add_result_to_cache'):
                                scanner.add_result_to_cache(asset.id, 'network', description, rule_type, match_value)

                            # 保存到数据库
                            try:
                                scan_result = await helpers.save_scan_result(
                                    asset=asset,
                                    module='network',
                                    scan_type='active',
                                    description=description,
                                    rule_type=rule_type,
                                    match_value=match_value,
                                    behavior=None,
                                    request_data=port_request_data,
                                    response_data=port_response_data
                                )

                                print(f"保存端口扫描结果: 资产={asset.host}, 描述={description}, 匹配值={match_value}")

                                # 提取端口号
                                port_numbers = []
                                for line in match_value.split('\n'):
                                    if ':' in line:
                                        port = line.split(':', 1)[0].strip()
                                        if port.isdigit():
                                            port_numbers.append(port)

                                # 用于展示的端口号字符串
                                port_display = ", ".join(port_numbers) if port_numbers else "未知端口"

                                # 发送扫描结果事件
                                await channel_layer.group_send(
                                    'data_collection_scanner',
                                    {
                                        'type': 'scan_result',
                                        'data': {
                                            'id': scan_result.id if scan_result else None,
                                            'asset': asset.host,  # 使用主机名而不是ID
                                            'asset_host': asset.host,  # 添加资产主机名
                                            'module': 'network',
                                            'module_display': '网络信息',
                                            'scan_type': 'active',
                                            'scan_type_display': '主动扫描',
                                            'description': description,
                                            'rule_type': rule_type,
                                            'match_value': match_value,
                                            'behavior': None,
                                            'request_data': port_request_data,
                                            'response_data': port_response_data,
                                            'scan_date': None,  # 由Django生成
                                            'is_port_scan': True,  # 标记为端口扫描结果
                                            'port_numbers': port_numbers,
                                            'port_display': port_display
                                        }
                                    }
                                )
                            except Exception as db_error:
                                print(f"保存端口扫描结果到数据库时出错: {str(db_error)}")
                                # 即使保存失败也不抛出异常，继续处理其他规则
                    else:
                        print(f"端口扫描无匹配结果")
                        # 即使没有匹配结果，也更新时间戳，避免频繁扫描
                        self.port_scan_timestamps[port_scan_key] = current_time

                except asyncio.TimeoutError:
                    print(f"端口扫描超时")
                    # 超时也更新时间戳
                    self.port_scan_timestamps[port_scan_key] = current_time
                    continue
                except Exception as e:
                    print(f"端口扫描出错: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    continue

                # 端口扫描规则处理完毕，继续下一个规则
                continue

            # 其他类型的主动扫描规则(非端口扫描)
            if not behaviors:
                print(f"规则 {rule_id} ({description}) 没有行为定义，跳过")
                continue

            print(f"准备对资产 {asset.host} 执行主动扫描规则 {rule_id} ({description})")
            print(f"行为列表: {behaviors}")

            for behavior in behaviors:
                try:
                    # 构建行为特定的缓存键
                    behavior_cache_key = f"{cache_key}-{behavior}"

                    # 构建主动扫描URL
                    target_url = urljoin(url, behavior)
                    print(f"执行主动扫描: {target_url}, 行为: {behavior}")

                    # 检查本地缓存
                    if behavior_cache_key in self.result_cache:
                        print(f"跳过本地缓存中已存在的主动扫描结果: {behavior_cache_key}")
                        continue

                    # 设置超时
                    scan_result = await asyncio.wait_for(
                        self.network_info_scanner.scan(
                            url=url,
                            behavior=behavior,
                            rule_type=rule_type,
                            match_values=match_values,
                            use_proxy=use_proxy,
                            proxy_address=proxy_address
                        ),
                        timeout=scan_timeout
                    )

                    # 如果有匹配结果，保存扫描结果
                    if scan_result:
                        match_value = scan_result.get('match_value', '')
                        print(f"主动扫描有匹配结果: {match_value}")

                        # 构建主动扫描的请求和响应数据
                        parsed_url = urlparse(url)
                        active_url = urljoin(url, behavior)
                        active_request_data = f"GET {active_url}\nHost: {parsed_url.netloc}\nUser-Agent: Mozilla/5.0...\nAccept: */*"
                        active_response_data = f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<active scan result containing: {match_value}>"

                        # 使用异步锁保护数据库操作
                        async with self.scan_lock:
                            # 二次检查数据库是否已存在相同结果
                            existing = await helpers.check_existing_result(
                                asset=asset,
                                module='network',
                                description=description,
                                rule_type=rule_type,
                                match_value=match_value
                            )

                            # 检查全局缓存
                            global_cache_hit = False
                            if scanner and hasattr(scanner, 'is_result_in_cache') and scanner.is_result_in_cache(
                                    asset.id, 'network', description, rule_type, match_value):
                                global_cache_hit = True
                                print(f"全局缓存命中: {behavior_cache_key}")

                            # 再次检查本地缓存(可能在锁等待期间被其他任务修改)
                            local_cache_hit = behavior_cache_key in self.result_cache
                            if local_cache_hit:
                                print(f"本地缓存命中(二次检查): {behavior_cache_key}")

                            # 如果缓存命中或数据库已存在，跳过
                            if global_cache_hit or local_cache_hit or existing:
                                print(f"跳过重复的主动扫描结果: 资产={asset.host}, 描述={description}, 行为={behavior}")
                                continue

                            # 添加到本地缓存
                            self.result_cache.add(behavior_cache_key)
                            self.result_cache.add(cache_key)  # 同时添加不带行为的基础缓存键

                            # 添加到全局缓存
                            if scanner and hasattr(scanner, 'add_result_to_cache'):
                                scanner.add_result_to_cache(asset.id, 'network', description, rule_type, match_value)

                            # 保存到数据库
                            try:
                                scan_result = await helpers.save_scan_result(
                                    asset=asset,
                                    module='network',
                                    scan_type='active',
                                    description=description,
                                    rule_type=rule_type,
                                    match_value=match_value,
                                    behavior=behavior,
                                    request_data=active_request_data,
                                    response_data=active_response_data
                                )

                                print(f"保存主动扫描结果: 资产={asset.host}, 描述={description}, 行为={behavior}, 匹配值={match_value}")

                                # 发送扫描结果事件
                                await channel_layer.group_send(
                                    'data_collection_scanner',
                                    {
                                        'type': 'scan_result',
                                        'data': {
                                            'id': scan_result.id if scan_result else None,
                                            'asset': asset.host,  # 使用主机名而不是ID
                                            'asset_host': asset.host,  # 添加资产主机名
                                            'module': 'network',
                                            'module_display': '网络信息',
                                            'scan_type': 'active',
                                            'scan_type_display': '主动扫描',
                                            'description': description,
                                            'rule_type': rule_type,
                                            'match_value': match_value,
                                            'behavior': behavior,
                                            'request_data': active_request_data,
                                            'response_data': active_response_data,
                                            'scan_date': None,  # 由Django生成
                                            'is_port_scan': False  # 标记为非端口扫描结果
                                        }
                                    }
                                )
                            except Exception as db_error:
                                print(f"保存主动扫描结果到数据库时出错: {str(db_error)}")
                                # 即使保存失败也不抛出异常，继续处理其他行为和规则
                    else:
                        print(f"行为 {behavior} 没有匹配结果")

                except asyncio.TimeoutError:
                    print(f"主动扫描行为 {behavior} 超时")
                    continue
                except Exception as e:
                    print(f"主动扫描行为 {behavior} 出错: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    continue