# PrivateLink 现有端点盘点与参考拓扑

此入口读取一个已存在的阿里云 PrivateLink Endpoint，不创建或删除端点、服务、网卡、安全组，也不修改云资源策略。平台分别调用 `GetVpcEndpointAttribute`、`ListVpcEndpointZones` 和 `ListVpcEndpointSecurityGroups`，完整观察后才发布本地台账和参考拓扑。

## 首次接入

1. 在阿里云连接中选择 PrivateLink，填写端点所在 `region_id`、明确的现有 `endpoint_id`，以及项目支持的 AccessKey 或 AssumeRole 凭据。配置的账号/凭据来源摘要只是来源标识，不表示已经证明 RAM 权限或账号归属。
2. 登录用户或平台 API Key 需要 `alicloud:read` 查看结果；执行盘点、取消和本地归档另需要 `alicloud:write`、`assets:write`。云凭据需要允许上述三个只读动作访问选定端点。云端拒绝后会保留上一份观察结果。
3. 保存并启用连接。真实模式下明确确认本次只读调用，再点击盘点。不要将服务的 Region 填作端点 Region；返回的 `ServiceRegionId` 可以是另一地域。
4. 看到成功回执后查看端点、可用区和安全组。仅端点纳管为 `Other` 资产，可用区、ENI、VSwitch、VPC、服务和安全组作为资源引用展示；点击资产可填写负责人等人工治理资料。

## Mock 模式

本地完整示例只有 `cn-hangzhou` 的现有端点 `ep-agf-demo`，其服务地域示例为 `cn-beijing`。设置 `mock=true`，使用这两个明确配置值，即可验证三个只读回执、分页完整性、资产发布和归档。示例域名为 `.invalid`，IPv4/IPv6 为文档示例地址；平台不会对这些地址发起访问。

未知 Mock 端点会失败，不会被自动创建。Mock 回执也走正式平台的领取、加密回执和审计路径；数据库部署会持久化这些事实，离线内存模式不承诺进程重启后保留。它只证明平台本地流程有效，不能用于证明生产网络、云权限或云资源存在。

## 如何理解结果

- `topologyAvailable=false`：当前配置尚未成功观察，或配置范围与保留快照不一致。此时端点为 `null`，图为空，不能把空图当作“云端没有关联资源”。
- 成功观察后 `zonesAvailable=true` 或 `securityGroupsAvailable=true` 配合明确 `[]`：对应列表已完整读取并确实返回零项。
- 详情缺失/null 的状态、地域、域名、资源 ID 等显示未知。服务地域只使用明确的 `ServiceRegionId`；不会默认使用端点地域。
- 边只来自上述公开动作返回的明确 ID，例如端点关联可用区、可用区返回 ENI/VSwitch。`Connected`、`Attached`、`Active` 都是云状态文本，不能证明数据包可达、开放端口、TLS、访问授权或安全组规则允许访问。`networkReachability` 和 `authorizationAllowed` 始终未知。
- “完整观察”表示按本次公开分页合同读取了两类子列表；云资源可能在分页期间改变，因此 `consistency=not_strong_snapshot`，不能称为云端强一致快照。

## 分页与失败恢复

每类列表最多20页，每页50项，每类最多1000项，两类合计最多2000项；整次执行最多110秒。安全组和可用区的公开文档分别说明没有下一页令牌值、或令牌为空时结束。平台接受末页 `NextToken` 缺失、null 或空字符串。

发布还需要可以核验的 `TotalCount`、真实数组、无重复 ID、各页总数一致，终止时累积数量与总数一致。这是平台选择的完整性要求，不表示官方所有返回字段都标为必填。缺少可核验总数、坏字段类型、令牌循环、超界、403、HTTP 错误或与配置矛盾的 Endpoint/Region 都不会被解释成零项，不会覆盖旧快照。

失败后先查看原请求回执，再核对连接、凭据和公开接口返回。修改配置或准备再次观察时，显式使用新的 `request_id`。数据库部署会永久保留原请求编号的领取事实；刷新、重复 POST、GET 回执和重启均不会重新派发原请求。离线内存模式仅保证当前进程中的领取事实。

取消只阻止后续读取和最终发布，已发送的只读请求不能撤回。配置停用、改版、范围切换、账号安全设置改变、Key 撤销或租约失效也会阻止继续读取/发布。旧配置快照仍保留用于本地恢复核查，但不会作为新范围的当前结果展示。

## 长期使用与显式归档

主请求台账最多512项或4MiB。选择已结束且非 active 的条目，确认归档，可一次归档1至100个 UUID，释放主台账容量。运行中条目即使租约已过期也须先显式取消。归档使用当前 `generation` 防止并发覆盖；版本冲突时重新读取，再重新确认。

归档保留每个编号的轻量永久事实和 `originalStatus`，旧编号 GET 返回 `status=archived`，仍永久禁止重新派发。归档不改变当前拓扑快照或资产；配置已停用时仍能执行本地归档。列表显示最近50项并保证 active 可见，历史编号可通过单笔回执入口查询。

已纳管端点再次观察只更新 `privatelink_` 来源观察和观察时间，不覆盖人工名称、负责人、数据分类、生命周期、标签、运行环境、接入地址或其他人工属性。来源缺失字段显式更新为 null，清除旧的来源观察。用户已删除的端点资产不会被盘点自动复活；应先显式恢复资产或核对来源，再用新请求重新盘点，期间整批旧快照保持不变。

数据库模式把配置/请求守卫、资产观察、加密快照、终态和成功审计放在同一事务，等待资源/审计锁后仍复查当前权限。离线模式以 ConfigStore→ApiStore 单机互斥一次发布候选及审计；提交身份在进入该同步临界区前复查，不能把离线模式当作跨实例治理保证。

## API 最小示例

使用已登录平台令牌，路径前缀为 `/api/v1`：

```text
GET  /alicloud/privatelink/inventory
POST /alicloud/privatelink/inventory/sync
     {"request_id":"<新UUID>","configuration_version":1,"confirm_live":true}
GET  /alicloud/privatelink/inventory/operations/<原UUID>
POST /alicloud/privatelink/inventory/operations/<原UUID>/cancel
     {}
POST /alicloud/privatelink/operations/archive
     {"expected_generation":2,"request_ids":["<已结束UUID>"]}
```

输入严格拒绝额外字段；租户由已认证身份决定，不能从请求 JSON 指定。盘点目标只从当前连接配置取得，不接受请求体中的其他端点或 URL。GET、取消和归档不发起云查询。

公开分页依据：[ListVpcEndpointZones](https://www.alibabacloud.com/help/en/privatelink/developer-reference/api-privatelink-2020-04-15-listvpcendpointzones)、[ListVpcEndpointSecurityGroups](https://www.alibabacloud.com/help/en/privatelink/developer-reference/api-privatelink-2020-04-15-listvpcendpointsecuritygroups)。
