"""
组件信息扫描模块：负责扫描网站组件和服务相关信息
"""
import asyncio
import json
from urllib.parse import urlparse, urljoin
from asgiref.sync import sync_to_async
from django.utils import timezone
from ..component_info import ComponentInfoScanner
from rules.models import InfoCollectionRule


class ComponentScanner:
    """组件信息扫描模块类"""

    def __init__(self):
        """初始化扫描器"""
        self.component_info_scanner = ComponentInfoScanner()

        # 添加结果缓存，避免重复发送相同结果
        # 格式: (asset_id, module, rule_type, description)
        self.result_cache = set()

        # 添加组件特征签名缓存
        self.signatures_cache = None

    def clear_cache(self):
        """清除缓存"""
        self.result_cache.clear()
        self.signatures_cache = None
        print("组件扫描器缓存已清除")

    async def scan(self, context):
        """
        扫描组件信息

        参数:
            context: 扫描上下文
        """
        # 获取上下文数据
        asset = context['asset']
        url = context['url']
        method = context['method']
        status_code = context['status_code']
        req_headers = context['req_headers']
        req_content = context['req_content']
        resp_headers = context['resp_headers']
        resp_content = context['resp_content']
        channel_layer = context['channel_layer']
        helpers = context['helpers']
        use_proxy = context['use_proxy']
        proxy_address = context['proxy_address']
        scan_timeout = context['scan_timeout']

        # 获取全局扫描器实例的方法用于检查和添加全局缓存
        scanner = context.get('scanner')

        # 格式化请求和响应数据，用于保存
        request_data = helpers.format_request_data(method, url, req_headers, req_content)
        response_data = helpers.format_response_data(status_code, resp_headers, resp_content)

        # 获取被动扫描规则
        passive_rules = await helpers.get_rules('component', 'passive')
        print(f"获取到 {len(passive_rules)} 条组件模块被动扫描规则")

        # 进行被动扫描
        await self._do_passive_scan(
            passive_rules=passive_rules,
            context=context,
            request_data=request_data,
            response_data=response_data,
            helpers=helpers,
            scanner=scanner
        )

        # 使用组件信息扫描器进行主动扫描
        active_rules = await helpers.get_rules('component', 'active')
        print(f"获取到 {len(active_rules)} 条组件模块主动扫描规则")

        # 如果没有规则，跳过主动扫描
        if not active_rules:
            print("没有组件模块主动扫描规则，跳过主动扫描")
            return

        # 进行主动扫描
        await self._do_active_scan(
            active_rules=active_rules,
            context=context,
            helpers=helpers,
            scanner=scanner
        )

    async def _do_passive_scan(self, passive_rules, context, request_data, response_data, helpers, scanner=None):
        """执行被动扫描，增加去重逻辑"""
        asset = context['asset']
        status_code = context['status_code']
        req_headers = context['req_headers']
        resp_headers = context['resp_headers']
        resp_content = context['resp_content']
        channel_layer = context['channel_layer']

        # 加载组件特征签名
        if self.signatures_cache is None:
            self.signatures_cache = await self._load_component_signatures()

        # 自动检测组件
        if self.signatures_cache:
            use_proxy = context.get('use_proxy', False)
            proxy_address = context.get('proxy_address', None)

            # 使用加载的特征签名进行组件检测
            detected_components = await self.component_info_scanner.detect_components(
                url=context['url'],
                use_proxy=use_proxy,
                proxy_address=proxy_address,
                signatures=self.signatures_cache
            )

            # 如果检测到组件，保存结果
            if detected_components:
                for component in detected_components:
                    # 创建缓存键
                    cache_key = (asset.id, 'component', 'auto_detect', component)

                    # 检查全局缓存和模块缓存
                    if (scanner and hasattr(scanner, 'is_result_in_cache') and
                        scanner.is_result_in_cache(asset.id, 'component', component, 'auto_detect', '')):
                        print(f"跳过全局缓存中已存在的组件检测结果: {component}")
                        continue

                    if cache_key in self.result_cache:
                        print(f"跳过模块缓存中已存在的组件检测结果: {component}")
                        continue

                    # 添加到模块缓存
                    self.result_cache.add(cache_key)

                    # 添加到全局缓存
                    if scanner and hasattr(scanner, 'add_result_to_cache'):
                        scanner.add_result_to_cache(asset.id, 'component', component, 'auto_detect', component)

                    # 检查是否已存在相同的结果
                    existing = await helpers.check_existing_result(
                        asset=asset,
                        module='component',
                        description=f"检测到组件: {component}",
                        rule_type='auto_detect',
                        match_value=component
                    )

                    if not existing:
                        # 保存检测结果
                        scan_result = await helpers.save_scan_result(
                            asset=asset,
                            module='component',
                            scan_type='passive',
                            description=f"检测到组件: {component}",
                            rule_type='auto_detect',
                            match_value=component,
                            behavior=None,
                            request_data=request_data,
                            response_data=response_data
                        )

                        # 发送扫描结果事件
                        if scan_result:
                            await channel_layer.group_send(
                                'data_collection_scanner',
                                {
                                    'type': 'scan_result',
                                    'data': {
                                        'id': scan_result.id,
                                        'asset': asset.host,
                                        'module': 'component',
                                        'module_display': '组件与服务信息',
                                        'scan_type': 'passive',
                                        'scan_type_display': '被动扫描',
                                        'description': f"检测到组件: {component}",
                                        'rule_type': 'auto_detect',
                                        'match_value': component,
                                        'behavior': None,
                                        'request_data': request_data,
                                        'response_data': response_data,
                                        'scan_date': None  # 由Django生成
                                    }
                                }
                            )

        # 手动规则扫描
        for rule in passive_rules:
            # 获取规则详情
            rule_id = rule['id']
            description = rule['description']
            rule_type = rule['rule_type']
            match_values = rule['match_values']

            # 创建缓存键
            cache_key = (asset.id, 'component', rule_type, description)

            # 检查全局缓存
            if scanner and hasattr(scanner, 'is_result_in_cache') and scanner.is_result_in_cache(asset.id, 'component',
                                                                                                 description, rule_type,
                                                                                                 ''):
                print(f"跳过全局缓存中已存在的组件结果: {cache_key}")
                continue

            # 检查模块级缓存
            if cache_key in self.result_cache:
                print(f"跳过模块缓存中已存在的组件结果: {cache_key}")
                continue

            # 根据规则类型进行匹配
            match_results = []
            if rule_type == 'status_code':
                # 状态码判断
                if str(status_code) in match_values:
                    match_results.append(str(status_code))

            elif rule_type == 'response_content':
                # 响应内容匹配
                for match_value in match_values:
                    if match_value.lower() in resp_content.lower():
                        match_results.append(match_value)

            elif rule_type == 'header':
                # HTTP头匹配 - 添加更强的安全检查
                for match_value in match_values:
                    try:
                        # 添加深度检查
                        is_valid_header_value = True

                        # 解析头部名称和值
                        if ':' in match_value:
                            header_parts = match_value.split(':', 1)
                            header_name = header_parts[0].strip()
                            header_value = header_parts[1].strip() if len(header_parts) > 1 else ''
                        else:
                            header_name = match_value.strip()
                            header_value = ''

                        # 检查头部名称是否有效
                        if not header_name:
                            is_valid_header_value = False

                        # 安全获取头部值
                        if is_valid_header_value:
                            # 检查请求头
                            req_header_value = None
                            if header_name in req_headers:
                                # 安全解码请求头值
                                if isinstance(req_headers[header_name], bytes):
                                    try:
                                        req_header_value = req_headers[header_name].decode('utf-8', errors='replace')
                                    except Exception as e:
                                        print(f"请求头 {header_name} 解码失败: {str(e)}")
                                        req_header_value = None
                                else:
                                    req_header_value = req_headers[header_name]

                                if req_header_value:
                                    if not header_value or header_value.lower() in req_header_value.lower():
                                        match_results.append(match_value)
                                        continue

                            # 检查响应头
                            resp_header_value = None
                            if header_name in resp_headers:
                                # 安全解码响应头值
                                if isinstance(resp_headers[header_name], bytes):
                                    try:
                                        resp_header_value = resp_headers[header_name].decode('utf-8', errors='replace')
                                    except Exception as e:
                                        print(f"响应头 {header_name} 解码失败: {str(e)}")
                                        resp_header_value = None
                                else:
                                    resp_header_value = resp_headers[header_name]

                                if resp_header_value:
                                    if not header_value or header_value.lower() in resp_header_value.lower():
                                        match_results.append(match_value)
                                        continue
                    except Exception as e:
                        print(f"处理HTTP头匹配值时出错: {str(e)}")
                        continue

            # 如果有匹配结果，保存扫描结果
            if match_results:
                # 只保存匹配到的值，避免保存所有匹配值
                match_value = '\n'.join(match_results)

                # 检查是否已存在相同的结果，避免重复添加
                existing = await helpers.check_existing_result(
                    asset=asset,
                    module='component',
                    description=description,
                    rule_type=rule_type,
                    match_value=match_value
                )

                # 添加到模块级缓存
                self.result_cache.add(cache_key)

                # 添加到全局缓存
                if scanner and hasattr(scanner, 'add_result_to_cache'):
                    scanner.add_result_to_cache(asset.id, 'component', description, rule_type, match_value)

                if not existing:
                    # 保存新的扫描结果
                    scan_result = await helpers.save_scan_result(
                        asset=asset,
                        module='component',
                        scan_type='passive',
                        description=description,
                        rule_type=rule_type,
                        match_value=match_value,
                        behavior=None,
                        request_data=request_data,
                        response_data=response_data
                    )

                    print(f"保存组件被动扫描结果: 资产={asset.host}, 描述={description}")

                    # 发送扫描结果事件
                    await channel_layer.group_send(
                        'data_collection_scanner',
                        {
                            'type': 'scan_result',
                            'data': {
                                'id': scan_result.id if scan_result else None,
                                'asset': asset.host,
                                'module': 'component',
                                'module_display': '组件与服务信息',
                                'scan_type': 'passive',
                                'scan_type_display': '被动扫描',
                                'description': description,
                                'rule_type': rule_type,
                                'match_value': match_value,
                                'behavior': None,
                                'request_data': request_data,
                                'response_data': response_data,
                                'scan_date': None  # 由Django生成
                            }
                        }
                    )
                else:
                    print(f"跳过重复的组件被动扫描结果: 资产={asset.host}, 描述={description}")

    async def _do_active_scan(self, active_rules, context, helpers, scanner=None):
        """执行主动扫描"""
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

            # 创建规则缓存键
            cache_key = (asset.id, 'component', rule_type, description)

            # 检查全局缓存
            if scanner and hasattr(scanner, 'is_result_in_cache') and scanner.is_result_in_cache(asset.id, 'component',
                                                                                                 description, rule_type,
                                                                                                 ''):
                print(f"跳过全局缓存中已存在的组件主动扫描结果: {cache_key}")
                continue

            # 检查模块级缓存 - 基本规则检查
            if cache_key in self.result_cache:
                print(f"跳过模块缓存中已存在的组件主动扫描结果: {cache_key}")
                continue

            if not behaviors:
                print(f"组件规则 {rule_id} ({description}) 没有行为定义，跳过")
                continue

            print(f"准备对资产 {asset.host} 执行组件主动扫描规则 {rule_id} ({description})")
            print(f"行为列表: {behaviors}")

            # 执行每个行为
            for behavior in behaviors:
                try:
                    # 创建行为特定的缓存键
                    behavior_cache_key = (asset.id, 'component', rule_type, description, behavior)

                    # 检查行为特定的缓存
                    if behavior_cache_key in self.result_cache:
                        print(f"跳过已缓存的组件行为: {behavior}")
                        continue

                    print(f"执行组件主动扫描: 行为={behavior}")

                    # 设置超时
                    scan_result = await asyncio.wait_for(
                        self.component_info_scanner.scan(
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
                        print(f"组件主动扫描有匹配结果: {match_value}")

                        # 构建主动扫描的请求和响应数据
                        parsed_url = urlparse(url)
                        active_url = urljoin(url, behavior)
                        active_request_data = f"GET {active_url}\nHost: {parsed_url.netloc}\nUser-Agent: Mozilla/5.0...\nAccept: */*"
                        active_response_data = f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<component active scan result containing: {match_value}>"

                        # 检查是否已存在相同的结果
                        existing = await helpers.check_existing_result(
                            asset=asset,
                            module='component',
                            description=description,
                            rule_type=rule_type,
                            match_value=match_value
                        )

                        # 添加到模块级缓存 - 同时缓存基本规则和行为
                        self.result_cache.add(cache_key)
                        self.result_cache.add(behavior_cache_key)

                        # 添加到全局缓存
                        if scanner and hasattr(scanner, 'add_result_to_cache'):
                            scanner.add_result_to_cache(asset.id, 'component', description, rule_type, match_value)

                        if not existing:
                            scan_result = await helpers.save_scan_result(
                                asset=asset,
                                module='component',
                                scan_type='active',
                                description=description,
                                rule_type=rule_type,
                                match_value=match_value,
                                behavior=behavior,
                                request_data=active_request_data,
                                response_data=active_response_data
                            )

                            print(f"保存组件主动扫描结果: 资产={asset.host}, 描述={description}, 行为={behavior}")

                            # 发送扫描结果事件
                            await channel_layer.group_send(
                                'data_collection_scanner',
                                {
                                    'type': 'scan_result',
                                    'data': {
                                        'id': scan_result.id if scan_result else None,
                                        'asset': asset.host,
                                        'module': 'component',
                                        'module_display': '组件与服务信息',
                                        'scan_type': 'active',
                                        'scan_type_display': '主动扫描',
                                        'description': description,
                                        'rule_type': rule_type,
                                        'match_value': match_value,
                                        'behavior': behavior,
                                        'request_data': active_request_data,
                                        'response_data': active_response_data,
                                        'scan_date': None  # 由Django生成
                                    }
                                }
                            )
                        else:
                            print(f"跳过重复的组件主动扫描结果: 资产={asset.host}, 描述={description}, 行为={behavior}")
                    else:
                        print(f"组件行为 {behavior} 没有匹配结果")

                except asyncio.TimeoutError:
                    print(f"组件主动扫描行为 {behavior} 超时")
                    continue
                except Exception as e:
                    print(f"组件主动扫描行为 {behavior} 出错: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    continue

    @sync_to_async
    def _load_component_signatures(self):
        """从数据库加载组件特征签名"""
        try:
            # 查找名为"组件特征签名"的规则
            rules = InfoCollectionRule.objects.filter(
                module='component',
                description__contains='组件特征签名',
                is_enabled=True
            ).first()

            if not rules:
                print("未找到组件特征签名规则")
                return {}

            # 解析规则内容
            try:
                signatures = json.loads(rules.match_values)
                print(f"成功加载组件特征签名: {len(signatures)} 个组件")
                return signatures
            except json.JSONDecodeError:
                print(f"组件特征签名格式错误，无法解析JSON")
                return {}

        except Exception as e:
            print(f"加载组件特征签名失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return {}