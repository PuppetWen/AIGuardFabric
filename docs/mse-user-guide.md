# MSE 界面操作指南 / MSE UI guide

本页说明控制台的实际操作入口。完整接口与盘点边界见 [MSE 服务盘点](mse-inventory-guide.md)。

## 中文

1. 打开阿里云页面的 **MSE 服务盘点**，或访问 `/alicloud?tab=mse`。查看清单、历史原回执和指南仅需 `alicloud:read`，不会调用云端，也不会读取需要写权限的连接配置。
2. 有 `alicloud:write` 时，在云连接列表选 MSE → 配置。填写地域和 **MSE 实例 ID**，明确选择 **默认命名空间** 或 **指定命名空间 ID**。默认选项发送 `namespace_id:""`；未选择不会自动视为默认。指定选项必须填写非空 ID。保存配置只校验并加密保存，不自动盘点。
3. 先使用 Mock 模式，在 **服务盘点** 或主页面 MSE 页签核对范围和版本。换账号、实例、命名空间、版本或模式后旧快照不作为当前清单；来源摘要只是配置来源的摘要，不证明实际 RAM 账号。
4. 点击 **读取完整服务并发布台账**。需要 `alicloud:read`、`alicloud:write` 和 `assets:write`；真实模式还须勾选当前范围的只读云请求与本地发布确认。厂商凭据需要 `ListAnsServices` 只读权限，不需要云服务写权限。
5. 原请求 UUID 会保留在输入框。超时、失败或断线后点击 **读取原请求回执**，不会再次发送盘点。刷新页面后可从最近50条回执选 **读取原回执**，或输入原 UUID。界面不会在失败后自动创建新请求。
6. 正在运行时可先读原回执，再显式确认 **取消原请求**。取消会阻止下一页和最终发布，但不能撤回已发送的只读页。关闭页面不是取消。租约过期显示 interrupted、但 `canCancel=true` 时存储记录尚未终态；需先取消才能归档。
7. 核对原请求终态后点击 **准备新盘点**，检查当前范围并再次确认真实模式，然后手动发起新编号。409 时先刷新本地清单与回执、读原编号、核对配置和范围；同范围活动请求要等待或取消。读取原回执失败保留同编号与已读结果。
8. 服务表每页50条。缺失实例数、健康数、集群数、地址、协议、环境、网络区域和授权显示未知，明确0与未知不同。用 **打开资产** 补充人工治理（需要 `assets:read`）；已有名称、类型、负责人、标签、分类和生命周期保留，清单未出现的资产不会被删除。
9. 活动请求台账上限512条或4MiB。勾选服务器标为可归档的终态回执，点击 **归档所选终态回执**，核对确认框数量后确认。每次最多100条；并发代次变化409时刷新并重新选择。没有自动归档，也不要求用户运行数据库命令。
10. 归档仅整理本地终态台账，保留原编号只读墓碑、原终态和历史 published 结果；不修改云、资产或最新快照，旧编号永不重新派发。停用连接后仍可读取、取消和归档，写动作权限要求不变。归档不等于云删除或资产归档。

最多20页、每页100项、2000项、110秒。列表完整仅表示按公开接口完成此次分页，不保证云端多页强一致快照。发布或 Mock 均不能证明调用授权。界面查询无云写入、任务重放或凭据回显。

## English

1. Open **MSE service inventory** on the AliCloud page or `/alicloud?tab=mse`. Inventory, original receipts and guides require only `alicloud:read`. They neither contact the provider nor read the connection configuration restricted to write permission.
2. With `alicloud:write`, select MSE → Configure in the connection list. Enter region and **MSE instance ID**. Explicitly select **Default namespace** or **Specific namespace ID**. Default sends `namespace_id:""`; no selection is not default. A specific namespace requires a nonempty ID. Saving validates and encrypts configuration without starting inventory.
3. Start with Mock and check scope/version in **Service inventory** or the main MSE tab. An old snapshot never becomes current after account, instance, namespace, version or mode changes. The source digest identifies configured credentials and does not prove a RAM account identity.
4. Click **Read complete services and publish inventory**. This requires `alicloud:read`, `alicloud:write` and `assets:write`. Live mode also requires explicit confirmation of cloud reads and local publication for the shown scope. Provider credentials need read-only `ListAnsServices` permission, not cloud service write permission.
5. Keep the original request UUID. On timeout, failure or disconnection click **Read original request receipt**; it does not dispatch inventory again. After a page reload choose **Read original receipt** from the recent 50 rows, or enter the original UUID. Failure never automatically creates a new request.
6. While running, read the receipt and confirm **Cancel original request** explicitly. Cancellation stops subsequent pages and publication but cannot recall an already-sent read. Closing the page is not cancellation. An expired lease displayed as interrupted with `canCancel=true` is not yet stored terminal; cancel before archiving.
7. After inspecting a terminal receipt, click **Prepare new inventory**, check scope and reconfirm Live mode, then manually start a new UUID. On HTTP 409 refresh local inventory/receipts, read the original ID and check configuration/scope. Wait for or cancel an active same-scope request. A failed receipt read retains the original ID and saved evidence.
8. Services use 50 rows per page. Missing instance/healthy/cluster counts, endpoint, protocol, runtime, network zone and authorization are unknown; observed zero differs from unknown. **Open asset** requires `assets:read` and lets you complete manual governance. Existing names, types, owners, labels, classification and lifecycle remain. Unlisted assets are not deleted.
9. The active request ledger holds 512 entries or 4 MiB. Select terminal records the server marks archivable. Click **Archive selected terminal receipts**, review the count and confirm. Each batch allows 100 IDs; on HTTP 409 from a concurrent generation change, refresh and reselect. Nothing archives automatically and no database command is required.
10. Archive only organizes the local terminal ledger, retaining read-only ID tombstones, original status and historical published results. Cloud, assets and the latest snapshot remain unchanged; an old ID never dispatches again. Read, cancellation and archive remain available after configuration disablement with the same permissions. Archive is neither cloud deletion nor asset archive.

Limits: 20 pages, 100 entries per page, 2000 services, 110 seconds. Complete listing means completed API pagination and not a strongly consistent cloud snapshot. Mock or publication does not prove authorization. UI reads do not write cloud, replay tasks or reveal credentials.
