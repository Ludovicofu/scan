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