# AgentTeams Worker 平台配额接入

本文说明如何让经过 AIGuardFabric 模型网关的真实请求使用平台配额。平台规则与 AgentTeams 云限额分别维护；采集审计日志不会替业务请求消耗模型网关额度。

## 能力与范围

| 平台范围 | Token `tokens` | 请求 `requests` | 并发 `concurrency` | 金额 `cost` |
|---|---|---|---|---|
| `tenant` | 当前租户共享 Token | 当前租户共享请求次数 | 当前租户未完成调用 | 当前租户共享微元金额 |
| `agent` | 每个已认证 Agent 独立 | 每个已认证 Agent 独立 | 每个 Agent 未完成调用 | 每个 Agent 独立 |
| `session` | 每个会话独立 | 每个会话独立 | 每个会话未完成调用 | 每个会话独立 |

`agent` 可填写当前租户有效 Agent 资产的 `target_id`，只限制这个 Worker；省略则分别限制所有已认证 Agent。租户、会话范围不接受 `target_id`。同一会话字符串在同一租户下共享会话额度，即使使用不同 Agent Key；不同租户互不共享。

`scope` 决定谁共享额度，`window` 决定时间桶。`minute/hour/day/month` 按 UTC 日历分桶；`session/total` 不按时间重置。`window=session` 本身不会按客户端会话分组：`scope=tenant,window=session` 仍是租户共享、不滚动的桶。并发计量表示尚未结束的调用，跨分钟或日期不会重新获得在途容量。

通用平台规则的 `limit=0` 表示本地不设上限，不能用于阻止调用。限制用量填正额度；要拒绝调用配置明确的拒绝策略，暂停规则设 `enabled=false`。动作 `deny/throttle/quota` 在超额时拒绝并返回 429；`audit/allow` 计量但不因这条规则拒绝。

| AgentTeams 云端治理 | 当前入口能力 |
|---|---|
| 单 Worker `token/day` 正限额 | 平台 Agent 目标规则绑定 → 读取差异 → 人工确认 → 写入及回读 |
| 租户/会话云限额、请求/并发/金额云限额 | 当前原生绑定入口不提供；不得把平台规则当作厂商已生效限制 |
| 云 `UsedAmount/OverLimit/RuleStatus` | 独立展示云观测，不合并平台已用量，不自动覆盖平台计数 |
| 失败业务任务重放 | 此配额入口不提供，也不会由日志或限额变化自动执行业务 |

云端其它限制须核对对应厂商契约。平台 `0` 的含义不能推广到云字段，当前 Worker 原生绑定不接受 `0`。原生治理步骤见 [Worker 配额治理指南](agentteams-quota-guide.md)。

## 控制台接入步骤

1. 选定租户，在“阿里云生态 → AgentTeams 盘点”完成当前账号/实例盘点，从 Worker 台账复制 **Agent 资产 UUID**。单独注册的 Agent 也可使用平台规则；云端名称、Team 名、SDK Task ID 均不是 `target_id`。
2. 在“模型网关”配置实际厂商模型、正确 Base URL、凭据与价格，核对处于 Live 模式。保存凭据后不会回显明文；先用受控测试请求验证模型与用量。全局 Mock 或 Mock 模型端点只能验证模拟行为。
3. 从 Worker 面板“创建平台配额”进入 `/runtime?quota_target=实际AgentUUID#quota-rules`，或直接在“运行时防护 → 运行时配额规则”新建。填写唯一名称、范围、维度、窗口和正额度；需要强制限制选拒绝动作。查看需 `quotas:read`，保存需 `quotas:write`。
4. 在“设置 → API Key”签发用于模型网关的最小权限 Key：`models:read`、`models:write`，**绑定同一 Worker 的 Agent 资产 UUID**。创建 Key 需 `settings:admin`；明文仅返回一次，保存到调用端秘密管理中。
5. 应用将模型请求发给平台 `/v1/chat/completions`，使用模型网关 Key。Worker 身份由 Key 绑定自动携带；不需要自行填写 `X-AGF-Agent`。需要会话额度时，为同一业务会话稳定发送 `X-AGF-Session`。
6. 在“运行时配额规则”按规则名称查看用量，在模型用量页面核对真实 Token、价格、Agent、会话及 Mock 标志。受控测试先成功一次，再超过正额度，确认 429 与上游请求数没有增加。测试结束按最新版本停用测试规则；保存相同规则不会清空已用量。

省略 `X-AGF-Session` 时，网关每次请求生成新会话标识。客户端改变会话字符串会进入新的会话桶，因此会话规则适合对业务会话分别分配额度；企业共享预算应另设租户或 Agent 规则。多条匹配规则同时约束调用，最先出现的超额错误不代表其它规则有剩余。

Agent 规则只约束归属该 Agent 的调用。直接访问厂商、未绑定的网关 Key、其它 Worker 的 Key 不会归入某个目标 Worker 的额度。需要限制所有平台调用时同时设置租户规则。

## 模型请求示例

下例只发送自己的模型业务请求。`AGF_MODEL_KEY` 是绑定 Worker 的网关 Key，不能替换为日志采集 Key。将地址和模型名改成自己的实际部署；不要把真实 Key 写入示例或日志。

```powershell
$base = 'http://localhost:8081'
$headers = @{
    Authorization = "Bearer $env:AGF_MODEL_KEY"
    'X-AGF-Session' = 'your-stable-business-session'
}
$body = @{
    model = 'your-configured-model-id'; max_tokens = 128
    messages = @(@{ role = 'user'; content = 'Your actual business input' })
}
$result = Invoke-RestMethod "$base/v1/chat/completions" -Method Post -Headers $headers `
    -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 6)
$result.usage
```

规则管理接口为 `GET/POST /api/v1/quotas`，详细字段和按版本修改示例见 [通用配额指南](quota-guide.md)。新建 `expected_version=0`；编辑发送最近读取的 `quota.version`。遇到 409，保留草稿、加载最新版本并人工合并，不盲目重试旧配置。

## 金额与实际结算

`cost` 的额度单位是微元：**1 元 = 1,000,000 微元**。模型端点价格字段 `prompt_micro_per_1k`、`completion_micro_per_1k`、`cached_prompt_micro_per_1k` 表示每 1000 Token 的微元价。填写自己的合同价；平台计价记录不是厂商账单或支付扣款。

例如输入和输出单价都为 1000 微元/1000 Token，上游返回输入 96、输出 4 Token，则本次为 100 Token、100 微元（0.0001 元）。价格为零或请求走 Mock 时，金额可以为零，不能用它验证真实金额上限。

平台先按输入估算、`max_tokens` 与候选模型价格预留，再按实际上游 usage 结算 Token/金额。因此剩余额度小于本次预留时会在调用上游前拒绝，即使实际生成可能更短。合理设置 `max_tokens`，不要通过重试降低或伪造已记录用量。

已完成调用归还并发。取消、上游异常或没有可信最终 usage 时，Token、次数、金额可能保守保留估算用量；不能将连接断开视为厂商未执行。并发释放与费用是否已发生是两个问题，重启不会自动把已用额度清零。

配额列表的 `used` 对一条 Agent/会话规则汇总当前窗口下各身份桶，用量总和可能大于每个身份的单独 `limit`。查看具体 Worker 时优先使用明确的 Agent `target_id` 并结合模型用量记录，不能把汇总余量解释为某个会话仍能使用的额度。

## SDK、采集 Key 与模型 Key

Python/Node AgentTeams SDK 用显式 Worker、Task、call 和 trace 上下文发送审计事件，见 [Python SDK](../sdk/agentteams/python/README.md)、[Node SDK](../sdk/agentteams/node/README.md) 与 [审计接入指南](agentteams-audit-guide.md)。SDK 采集本身不会把业务模型客户端自动改到平台，也不从日志反推可信 Token 或费用。

日志采集 Key 的最低权限为 `sources:write`，按租户授权，不是源专用 Key；日志源与 binding 另行限制接入范围。模型网关 Key 使用 `models:read/models:write` 并绑定 Agent。分别保管两类 Key；审计 SDK 的 queue/binding/trace 与网关 `X-AGF-Session` 不是同一个身份或额度桶。消息、任务、心跳日志不会当作模型调用 Token 收费。

## 验收边界

回环测试可验证真实 HTTP 分发、非 Mock 正价结算、12 种平台范围/维度、429 不发送额外上游请求、并发归还、SQL 多实例竞争和持久化。它不证明真实厂商权限、余额、账单或 AgentTeams 云限制已经生效；使用真实云时仍需按对应入口完成授权和人工验证。

## English reference

Platform quota scopes are tenant-wide, per authenticated Agent, or per `X-AGF-Session`. All three support tokens, requests, in-flight concurrency and integer micro-yuan cost. `target_id` is accepted only for an active Agent asset; omitting it applies the limit independently to every authenticated Agent.

Scope selects shared identity; window selects the time bucket. UTC minute/hour/day/month buckets roll, while session/total do not roll by time. A tenant quota with a session window remains shared across sessions. Without `X-AGF-Session`, each model request gets a fresh session ID. Use tenant/Agent quotas for budgets that clients must not reset by choosing new session IDs.

Create a real priced model endpoint, then a positive deny quota in Runtime protection. Issue a separate gateway Key with `models:read/models:write`, bind it to the Worker’s Agent asset, and route the actual model client through `/v1/chat/completions`. Audit collector Keys use `sources:write` and do not automatically route models or meter their token usage. Creating a Key requires `settings:admin`; viewing/updating quota rules requires `quotas:read/quotas:write`.

Local `limit=0` means no local cap. Disable a rule explicitly to pause it; configure an explicit deny policy to block calls. This does not define the meaning of any cloud limit. The current native Worker binding supports only a positive Agent-targeted token/day/deny rule; it does not synchronize tenant/session, request, concurrency or monetary cloud limits.

Cost uses micro-yuan: 1 yuan equals 1,000,000 micro-yuan. Prices are micro-yuan per 1000 tokens. Admission reserves estimated input plus requested maximum output, then settles known actual usage. Unknown usage can retain estimates; disconnection does not establish that the provider never executed. Completed/cancelled gateway work releases concurrency separately from any retained usage charge.

Use current rule versions on edits. On409 load and merge the latest rule; on429 check the matching scope, session and reserved maximum before retrying. Per-Agent/session list usage sums multiple independent buckets. Loopback and Mock validation do not establish real vendor authorization, billing or live cloud enforcement.
