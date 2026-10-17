# AgentTeams Worker 配额接入指南

平台规则负责经过平台网关的调用，Worker 云限制由 AgentTeams 执行。当前可把单个 Worker 的平台日 Token 上限显式同步到云端，并读取云限制、发现差异及产生关联资产的告警。两侧用量分别记录，配置一致不代表所有流量已接管或云端预算执行已经验证。

## 准备接入

1. 在控制台选择正确组织，打开“云服务接入与操作 → 配置与接入”，保存 AgentTeams 连接，再到“台账同步”执行完整盘点。确认 Worker 已映射成当前组织的有效 Agent 资产。
2. 在“云服务接入与操作 → Worker 配额治理”选择 Worker。首次练习使用 Mock；Mock 的云状态会持久保存和回读，界面始终带模拟标记。Live 使用已配置的云凭据，并需要显式确认每次读取或写入。
3. 管理规则及绑定需要 `quotas:read`、`quotas:write`、`alicloud:read`、`alicloud:write`；只查看需要两类读取权限。云端读取另外需要 `alicloud:write`，因为该操作会保存观察、审计及差异预览。查看漂移告警需要 `alerts:read`。
4. 点击“创建平台配额”，进入“运行时防护 → 运行时配额规则”。填写名称和正整数额度，核对预填的 Agent 目标、`tokens`、`day`、`deny`，启用并保存。打开创建链接只预填表单。详细规则和版本处理见[运行时配额指南](quota-guide.md)。

不能选择租户共享规则、全部 Agent 的规则、其它维度/周期或停用规则充当一个 Worker 的云限额。此入口只支持该 Worker 专属的 `Agent / tokens / day / deny` 正整数规则。

## 按页面完成一次同步

1. 回到“Worker 配额治理”，刷新规则，选择匹配的平台规则并保存绑定。保存绑定只改变平台配置；界面此时应显示“未验证”。
2. 点击“读取云端”，确认执行只读 `GetWorker`。检查 Worker 资产、云实例范围、平台限额以及云端 `UsageLimit`、`LimitType`、`PeriodType`。读取差异会生成 `quota-drift` 告警；有权限时可点击进入告警详情。
3. 云端应返回完整正限额 `token/day`。缺少完整限制时先到厂商控制台配置；其它云周期当前仅可核对，不能从本入口同步。`RuleStatus`、`UsedAmount`、`OverLimit` 是独立云观测，平台不会把它们写回。
4. 检查差异后点击“检查差异并同步”，核对确认窗口中的目标和三项配置，勾选确认，再点击“确认写入并回读”。预览仅有效五分钟；规则或绑定版本改变、预览过期或已使用时须重新读取。
5. 服务先再次读取，确认云配置仍与预览一致，再按平台上限执行 `UpdateWorker`，最后调用 `GetWorker` 验证。最终“回读已验证”表示本次限制回读匹配；无需更新时不发 `UpdateWorker`。成功回读匹配后，本绑定的漂移告警关闭。

平台只更新确认的 `UsageLimit`，保留读取到的完整可写 `LimitType`、`PeriodType`。云调用与配置提交使用版本核对；云操作期间不长期持有数据库事务。

## 让平台配额实际约束调用

到“设置 → API Key”创建用于模型网关的最小权限 Key，把 Key 绑定到同一 Worker 的 Agent 资产，参照[用户操作手册](user-handbook.md#4-模型网关与应用)配置平台地址和模型。经该 Key 发往平台的模型调用会归入此 Worker 的平台规则，超额拒绝返回 HTTP 429；使用另一个 Worker 的 Key 会计入它自己的范围。

直接调用厂商、绕过平台或使用未绑定该资产的 Key，不会归入这一目标规则。平台采用 UTC 自然日；云用量及其周期按厂商返回展示，不能用一侧的已用量推算另一侧剩余额度。保存同名平台规则保持原用量；重新绑定同步关系不清空平台配额。

## 出错、停用与恢复

| 页面状态或错误 | 操作方法 |
|---|---|
| 409、预览过期或版本改变 | 保留需修改的内容，刷新平台规则/盘点/绑定，重新读取并核对差异，再显式确认 |
| “执行中”且租约有效 | 等待并刷新持久回执；当前不能再次读取或写入同一 Worker |
| 结果不确定、超时或回读失败 | 核对操作与请求 ID，刷新回执。服务器允许后手动重新读取实际云状态；不要直接重发旧写操作 |
| 已收到写入成功回执，但最终未验证 | 写入可能成功，最终配置仍需重新读取；成功写入回执不能替代匹配回读 |
| 绑定失效 | 核对云账号、实例、模式、盘点映射、Worker 生命周期与规则，更新盘点后重新绑定 |
| 412 | 检查规则兼容性、完整云限制及 Live 操作确认 |
| 403 | 检查组织和管理权限；其它组织的资产、规则和回执不可使用 |

同一写请求 ID 不会重放云写入，且不能改参数重用；网络或执行结果未知时先核对实际状态。中断操作的有效租约到期后，刷新页面可恢复手动读取，恢复过程不自动修改云端。

停用绑定保留历史观察和回执，不删除或修改云限额，也不自动停用平台规则。要暂停平台拒绝，在“运行时配额规则”按当前版本停用规则。云限制需单独在厂商控制台管理。更换云账号、实例、Mock/Live 模式或 Worker 映射后，旧绑定不能继续写入。

该入口不提供任务重放、云用量合并、自动 SDK 注入或其它维度的自动同步；这些能力须按对应需求单独完成。当前冲突处理使用平台规则作为同步目标，云端差异先告警并人工确认，不自动导入云设置覆盖平台规则。

## API 接入

完整接口与请求字段见当前实例的 `/api/v1/openapi.json`。路径中的 `{id}` 是盘点映射的 **Agent 资产 UUID**，不是云 Worker 名称或绑定 ID。

| 方法与路径 | 用途与版本 |
|---|---|
| `GET /api/v1/alicloud/agentteams/worker-quotas` | 读取当前 Worker、兼容规则、绑定、观察及最近回执 |
| `PUT /api/v1/alicloud/agentteams/worker-quotas/{id}` | 保存/停用；发送 `expected_version`、`quota_id`、`quota_version`、`enabled` |
| `POST .../{id}/observe` | 发送新的 `request_id`、当前 `expected_binding_version`、`expected_quota_version`、`configuration_version`，Live 另填 `confirm_live: true` |
| `POST .../{id}/sync` | 在上述版本字段基础上发送实际读取的 `preview_id`，使用独立新的 `request_id`，Live 另填 `confirm_live: true` |

新绑定的 `expected_version` 为 `0`；已有绑定使用 GET 返回的当前 `version`。从服务器列表与观察响应读取真实 ID 和版本，勿使用演示 UUID。响应 HTTP 200 后仍需检查 `operation.status` 和 `mocked`；只有 `verified` 代表限制回读一致。

## English quick start

Select your tenant, configure AgentTeams and complete inventory. In **Cloud connections and operations → Worker quota governance**, select the mapped Worker and create a positive, enabled, targeted **agent / tokens / day / deny** rule under Runtime protection. Save the binding, explicitly read cloud limits, review the five-minute preview, then confirm synchronization and final readback. Live reads and writes require explicit confirmation.

Bind the calling gateway API key to the same Agent asset to attribute platform usage. Platform UTC-day usage and provider usage remain separate. A successful write receipt is insufficient: inspect the final `verified` state. After a timeout or uncertain result, refresh the durable receipt and explicitly read cloud state before any new write. An old request is never replayed automatically. Disabling a binding preserves cloud limits and does not disable the platform rule. Other quota dimensions, automatic SDK instrumentation and task replay remain outside this workflow.
