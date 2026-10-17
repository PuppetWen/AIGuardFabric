# 回执核查与本地恢复 / Receipt review and local recovery

中文操作入口：`/alicloud` → 云连接「配置与接入」→「操作与回执」；
`/integrations` → 选择适配器「编辑」→「业务调用与记录」。两处均提供可展开的回执指南。
历史元数据需要 `alicloud:read` 或 `integrations:read`。单笔回执明细及本地恢复需要对应的
`alicloud:write` 或 `integrations:write`。
所有请求只处理当前租户和所选服务的操作编号。

| 本地阶段 | 含义与操作 |
|---|---|
| `running` | 执行中或曾中断，没有已知暂存回执。只读刷新；核对外部状态，不能重发原操作 |
| `pending_audit` | 已加密暂存执行结果，但本地回执发布与审计未完成。页面 `status=uncertain`；`provider_status` 只是保留的执行分类，不能当成本地成功或外部最终成功 |
| `complete` | 本地回执与审计已提交。继续分别核对 `status` 和 Mock/Live；`uncertain` 仍不证明外部成功 |

1. 点「刷新记录」，再在原操作中点「查看」；核对请求编号、原配置版本和 Mock/Live。
2. 点「重新读取回执」只发 GET。记录/回执读取不补交审计、不调用供应商，也不自动恢复。
3. 仅 `pending_audit` 显示「恢复本地回执与审计」。具有写权限时，明确点击后才 POST 空请求体。
   此操作只发布已经加密暂存的本地回执与审计，不调用云 API、STS、适配器，也不重发原业务。
4. 存储或审计失败会保留当前回执。修正原因后先重新读取，再明确重试本地恢复；不要点原业务执行按钮。
5. 停用、换配置版本或清除凭据后，仍可读取和恢复旧回执。恢复无需当前配置版本、凭据或真实调用确认。
   切换租户/登录会话会清空页面内的旧结果；迟到响应不会进入新会话。

API：`GET /api/v1/alicloud/connections/{name}/operations/{id}` 和
`GET /api/v1/integrations/adapters/{name}/operations/{id}` 严格只读。
同路径追加 `/recover` 后 POST `{}` 显式恢复。已完成记录再次恢复返回原回执且不新增审计；
没有可恢复暂存结果时返回 412。403/404/409/412 均不能证明外部操作未发生，不能作为重发依据。
这与原生 Team 的只读云端回读/台账发布恢复是不同入口；见 [团队维护指南](agentteams-team-management-guide.md)。

## English

Open `/alicloud` → Configure a cloud connection → Operations, or `/integrations` → Edit an adapter → Operations and history.
Expand “Receipt states and local recovery guide”. History metadata requires `alicloud:read` or `integrations:read`.
Receipt details and local recovery require the corresponding `alicloud:write` or `integrations:write` in the selected tenant.

1. Refresh history, open View, and verify the request ID, original configuration version and Mock/Live mode.
2. Read receipt again sends only GET. Reading never publishes audit, contacts the provider or automatically recovers.
3. `pending_audit` means an encrypted receipt is retained, while local publication is incomplete. Its visible status remains
   `uncertain`, even when the retained `provider_status` says `succeeded`. Explicitly choose Recover local receipt and audit.
4. Recovery sends an empty POST body to the receipt path plus `/recover`. It publishes local receipt and audit only;
   it does not contact cloud APIs, STS or adapters and never repeats the business operation. Failure preserves the displayed receipt.
   Fix the local cause, read again and explicitly retry local recovery.
5. `running` without a retained receipt cannot be recovered. `complete` means local publication completed; an `uncertain`
   provider outcome remains uncertain. Check the external system before considering any separately reviewed new operation.
6. Disabled/changed connections and cleared credentials do not block old receipt review or recovery. No current configuration
   version or live-call confirmation is needed. Changing tenant or sign-in discards this page's old results and ignores late replies.

Already complete recovery adds no audit. A 412 means there is no known local receipt to publish; 403/404/409/412 do not establish
that the external operation had no effect. Never use these responses as a reason to replay a write.
