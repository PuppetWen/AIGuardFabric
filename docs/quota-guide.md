# 运行时配额操作指南

“设置 → 网关配额”管理模型网关的默认 Token 与并发额度；“运行时防护 → 运行时配额规则”管理通用运行时配额和用量。本文的 `/api/v1/quotas` 用于管理通用配额，包括模型调用和 MCP 检查实际使用的规则。两类配置的接口、版本号和额度口径分别维护。

## 在控制台操作

1. 打开“运行时防护”，找到“运行时配额规则”，先按名称搜索并检查已有规则、版本和用量。
2. 有 `quotas:write` 的成员点击“新建配额”，填写名称、作用域、维度、窗口、额度与动作，确认后点击“保存配额”。只读成员只能查看。
3. 创建单个 Worker 规则时，可从 Worker 配额绑定面板点击“创建平台配额”；地址 `/runtime?quota_target=Agent资产UUID#quota-rules` 会预填 Agent 目标、Token、日窗口和拒绝动作。必须自己填写名称和正额度，打开页面不会创建或调用云端。
4. 已有规则点击“编辑”可修改额度、软阈值、动作或启停。名称、作用域、目标、维度和窗口保持，避免保存时意外改变计量范围；需要新范围请新建规则。
5. 若别人先保存，页面保留草稿并禁止再次提交旧版本。复制需保留的修改，点击“加载最新规则”并确认，核对后人工合并，再保存。

后台刷新不会覆盖正在编辑的草稿；切换组织或打开另一 Worker 的创建链接会重新开始该范围的编辑。保存期间表单锁定，连续点击不会重复提交。

若操作等待登录刷新期间切换组织或重新登录，控制台会取消原页面尚未发送的请求，并提示“组织或登录状态已改变”。重新打开当前组织的页面、核对内容后再操作；不要照搬上一组织的草稿。已发送请求始终保留发起时的组织，迟到的数据不会显示到另一组织。

## 准备与选择范围

1. 在控制台选定组织，到“设置 → API Key”创建具有 `quotas:read`、`quotas:write` 的管理 Key。只读查看只需 `quotas:read`。普通成员及 Key 只能维护所属组织。
2. 确定名称、作用域、计量维度和窗口。同一组织中名称唯一；同名保存是修改，换名称会新增另一条规则。
3. `tenant` 是整个组织共享额度；`agent` 分别限制已认证的 Agent；`session` 分别限制会话。按 Agent 管理时，客户端 Key 应绑定对应 Agent，参见 [案件处置指南](case-response-guide.md)。
4. 只限制一个 Worker 时，使用 `scope: "agent"` 并填写台账中该 Worker 的 `target_id`。目标必须是当前组织有效的 Agent 资产。省略 `target_id` 会分别限制所有 Agent；`tenant` 和 `session` 不接受此字段。

| 字段 | 可选值及含义 |
|---|---|
| `dimension` | `requests` 请求次数、`tokens` Token 数、`concurrency` 未完成并发、`cost` 微元金额 |
| `window` | `minute`、`hour`、`day`、`month` 按 UTC 分桶；`session`、`total` 不按时间重置 |
| `limit` | 非负上限；通用运行时配额的 `0` 表示本地不设上限，不能用于阻止调用。限制用量应填正额度；需要拒绝调用请配置明确的拒绝策略。暂停此规则应设置 `enabled: false` |
| `soft_threshold` | 非负且不超过上限；`0` 不启用软阈值，省略默认上限约 80% |
| `action` | `deny`、`throttle`、`quota` 超额时拒绝；`audit`、`allow` 仍记录用量但不因该规则拒绝 |
| `expected_version` | 编辑时填写最近读取的 `quota.version`；新建填 `0`，成功后使用新版本 |

并发在调用完成后归还；取消、异常或状态未知时可能保守占用至租约到期。修改相同名称的额度保持规则 ID、创建时间和已有用量；不会因保存配置清空计数。改变作用域、目标、维度或窗口会改变后续计量范围，应先核对当前调用与原用量。

上述 `0` 语义只用于平台通用运行时配额，不代表云端 Worker 限额的含义。当前 AgentTeams 原生绑定只接受正整数的 `tokens/day/deny` 配额，不能把 `0` 同步到云端；其它云端限制须按厂商契约核对。

## 新建、读取与修改

以下 PowerShell 使用自己部署的控制台地址。先把刚创建的 Key 放入本次终端会话的 `AGF_QUOTA_TOKEN`，不要把实际 Key 写入示例文件。

```powershell
$base = 'http://localhost:8081'
$headers = @{ Authorization = "Bearer $env:AGF_QUOTA_TOKEN" }
$body = @{
    name = 'test-requests-total'; scope = 'tenant'; dimension = 'requests'
    window = 'total'; limit = 50; soft_threshold = 40
    action = 'deny'; enabled = $true; expected_version = 0
}
$created = Invoke-RestMethod "$base/api/v1/quotas" -Method Post -Headers $headers `
    -ContentType 'application/json' -Body ($body | ConvertTo-Json)
$created.quota | Select-Object id, name, limit, version

$list = Invoke-RestMethod "$base/api/v1/quotas?q=test-requests-total" -Headers $headers
$current = ($list.items | Where-Object { $_.quota.name -eq $body.name }).quota
$body.expected_version = $current.version
$body.limit = 75
$saved = Invoke-RestMethod "$base/api/v1/quotas" -Method Post -Headers $headers `
    -ContentType 'application/json' -Body ($body | ConvertTo-Json)
$saved.quota | Select-Object id, name, limit, version
```

单个 Worker 的日 Token 规则示例：先从资产台账详情复制实际 Agent ID，再替换示例中的占位值。

```json
{"name":"worker-token-day","scope":"agent","target_id":"实际 Agent UUID","dimension":"tokens","window":"day","limit":100000,"action":"deny","enabled":true,"expected_version":0}
```

POST 是完整配置保存，编辑时保留原先的作用域、维度、窗口、目标和动作，只改变需要修改的字段。`GET /api/v1/quotas` 返回分页列表，条目中 `quota.version` 是该规则的版本，`used`、`remaining` 是当前用量。Agent 全局规则的汇总用量会包含多个 Agent，不能把它当作单个 Worker 的剩余额度。`GET /api/v1/quotas/snapshot` 用于按维度概览；维护具体规则应使用列表中的名称、ID 与版本。

## 冲突与核对

- **HTTP 409**：规则已更新。保存当前草稿，重新 GET，比较最新设置并人工合并，使用最新版本再保存；不要自动强制覆盖。
- **HTTP 400**：检查名称、数值、目标以及 `expected_version`。已有配置即使是迁移后的版本 `0`，编辑也必须明确提交 `0`；漏填会被拒绝。
- **HTTP 403**：核对管理 Key 的权限和所属组织。另一组织的 Agent ID 不能用作目标。
- **HTTP 429**：在运行时事件核对实际触发的规则、作用域和窗口，再决定等待窗口还是修改额度。
- **服务或数据库错误**：先重新读取确认当前版本，再决定重试。生产数据库中，配置和成功审计在同一事务提交；审计失败不会保存新额度或推进版本。成功变更可在审计中心按 `quota` 目标核对操作者、名称和保存参数。

## English quick start

Create a tenant-owned management key with `quotas:read` and `quotas:write`. Read `GET /api/v1/quotas`, then send a complete definition to `POST /api/v1/quotas` with its current `quota.version` as `expected_version`; use `0` for creation. A stale edit returns 409. Reload and manually merge your draft before retrying. Editing the same name preserves the quota ID and consumed usage. Generic runtime `limit: 0` sets no local limit and does not block calls. Use a positive allowance to limit consumption, an explicit deny policy to block calls, or `enabled: false` to suspend this rule. This does not define a cloud Worker's zero-limit semantics: the current AgentTeams native binding requires a positive `tokens/day/deny` limit.

For one Worker, set `scope: "agent"` and `target_id` to its active Agent asset in the selected tenant. Omitting the target applies a separate quota to each authenticated Agent. Bind a targeted, positive, enabled `tokens/day/deny` rule to the matching Worker through the AgentTeams integration; follow the [Worker quota guide](agentteams-quota-guide.md) for explicit observation, synchronization and readback. Quota configuration success and its audit commit together in PostgreSQL; offline memory mode is temporary and does not provide database durability.
