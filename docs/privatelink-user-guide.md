# PrivateLink 界面操作指南 / PrivateLink UI guide

## 中文

先使用固定 Mock 示例核对流程：配置地域 `cn-hangzhou`、已有端点 `ep-agf-demo`、`mock=true`。该示例仅响应 `GetVpcEndpointAttribute`、`ListVpcEndpointZones`、`ListVpcEndpointSecurityGroups` 三个只读动作，不合成未知端点。服务地域字段为 `cn-beijing`，独立于端点地域；安全组地域、网络可达和调用授权仍为未知。以下真实模式步骤使用云控制台中实际存在的端点。

1. 在目标地域的云控制台复制**已有端点 EndpointId**。本功能只盘点所选端点，不创建端点、修改路由或测试实际网络流量。
2. 有 `alicloud:write` 时，打开阿里云连接列表 → PrivateLink → 配置，填写地域和已有端点 ID，选择凭据来源并保存启用。未填写端点 ID 不会自动选目标；若要先验证，使用上面的固定 Mock 参数。
3. 打开 `/alicloud?tab=privatelink`。读取本地观察和原回执仅需 `alicloud:read`，不会访问云或读取秘密配置。盘点、取消和归档还需 `alicloud:write`、`assets:write`。
4. 云凭据需 `GetVpcEndpointAttribute`、`ListVpcEndpointZones`、`ListVpcEndpointSecurityGroups` 读取权限。核对 RAM 的所选资源范围；真实模式须明确确认范围，然后手动读取端点及子列表并发布一个端点资产。
5. 端点详情、子列表和图只展示接口返回的标识和字段。缺失值保持未知，观察到的空列表与未知不同；只有端点关联平台资产。其他节点是云资源引用，不是新增的 Agent/MCP 或已查询的独立资源。
6. 点击图节点查看其真实邻接关系和来源 API；节点、关系与子列表按50条分页。Connected 或 Attached 只是云状态，**网络可达、实际路由、端口/协议和调用授权仍未知**。API 公网/VPC 接入点只控制云管理接口入口。
7. 保存原 UUID。失败、断线或超时后**读取原请求回执**，不会再次盘点。刷新页面后从最近50条回执或原编号恢复；没有自动重发。运行时可显式取消，关闭页面不是取消。取消不撤回已发送的读取。
8. 核对终态后**准备新盘点**，重新检查范围和真实确认，再手动发起新 UUID。409 先刷新本地记录、读原回执，核对配置范围或取消活动请求。失败保留上一完整观察与人工字段，不用部分页覆盖。
9. 活动台账上限512次请求/4MiB；选择服务器标为可归档的终态、核对数量后明确归档，每批最多100条。过期但仍可取消的记录尚未终态，先取消；并发代次409刷新重选。不要求数据库清理命令，也没有后台归档。
10. 归档保留原编号只读墓碑、原终态和历史 published，不修改云、资产或最新观察。原编号永久不重新派发。停用连接后仍可读取历史、取消和本地归档，写权限要求不变。范围摘要不证明 RAM 账号或网络授权。

单个子列表最多20页、每页50项、1000条；全轮110秒。完整分页不保证云端多页强一致。本页不推断数据包路径、跨账号归属或网络安全策略有效性。

原编号、回执和墓碑的持久跨实例保证需要配置数据库，并由实例使用同一数据库。未配置数据库的离线模式只在当前进程保留这些事实，进程重启后不能恢复。Mock 只是云调用模式，不保证持久存储。

## English

Start with the fixed Mock example: region `cn-hangzhou`, existing endpoint `ep-agf-demo`, and `mock=true`. It responds only to the three read actions `GetVpcEndpointAttribute`, `ListVpcEndpointZones` and `ListVpcEndpointSecurityGroups`; unknown endpoints are not synthesized. Its service-region field is `cn-beijing`, independent of the endpoint region. Security-group region, reachability and authorization remain unknown. The Live steps below use an endpoint that actually exists in the cloud console.

1. Copy an **existing EndpointId** from the cloud console in the selected region. This feature inventories one endpoint; it does not create endpoints, change routes or send network probes.
2. With `alicloud:write`, open Alibaba Cloud connections → PrivateLink → Configure. Enter region and the existing endpoint ID, choose the credential source, save and enable. An omitted ID never selects a target. For Mock, use the fixed example above.
3. Open `/alicloud?tab=privatelink`. Local observations and original receipts require only `alicloud:read`, with no provider or secret configuration read. Inventory, cancellation and archive also require `alicloud:write` and `assets:write`.
4. Cloud credentials need read permissions for `GetVpcEndpointAttribute`, `ListVpcEndpointZones` and `ListVpcEndpointSecurityGroups`. Review RAM permissions for the chosen scope. Confirm Live scope explicitly, then manually read the endpoint/child lists and publish one endpoint asset.
5. Details, child lists and graph show only returned identifiers and fields. Missing values remain unknown; observed empty lists differ from unknown. Only the endpoint has a platform asset. Other nodes are cloud resource references, not newly created Agents/MCP servers or independently queried resources.
6. Select a graph node to inspect its actual adjacent references and source API. Nodes, edges and child lists use 50-row pages. Connected/Attached are cloud observations; **reachability, actual routes, ports/protocols and authorization remain unknown**. Public/VPC API selection controls only the management API endpoint.
7. Retain the original UUID. After failure, timeout or disconnection, **Read original request receipt** never dispatches again. Restore after reload from the recent 50 records or original ID input. Cancellation is explicit; closing the page is not cancellation and already-sent reads cannot be recalled.
8. After a terminal result, **Prepare new inventory**, check scope and reconfirm Live mode, then manually dispatch a new UUID. On HTTP 409 refresh local records, read the original receipt and check scope or cancel the active request. Failed/partial pages retain the previous complete observation and manual fields.
9. The active ledger holds 512 requests/4MiB. Select server-marked archivable terminal records and confirm their count; a batch permits 100 IDs. Cancel an expired but cancellable nonterminal request first. On a generation 409 refresh and reselect. No database cleanup command or background archive is required.
10. Archive retains read-only ID tombstones, original final status and historical published results. Cloud, assets and latest observations remain; an original ID never dispatches again. History reads, cancellation and local archive remain available after disabling the connection with the same write permissions. A scope digest does not establish RAM identity or network authorization.

Each child list permits 20 pages, 50 entries per page and 1000 records; the whole run allows 110 seconds. Complete pagination is not a strongly consistent cloud snapshot. No packet path, cross-account ownership or effective network policy is inferred.

Persistent original-ID, receipt and tombstone guarantees across instances require a configured database shared by those instances. Without a database, offline mode retains these facts only in the current process and cannot restore them after restart. Mock is a cloud-call mode and does not guarantee persistent storage.
