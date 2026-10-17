# Scheduler 六类任务接入 / Scheduler six-task setup

入口：`/alicloud` → “云服务接入与操作” → SchedulerX3 行“配置与接入” → “接入指南” → “定时任务接入步骤 / 准备云 HTTP 回调配置”。当前连接 Drawer 需要 `alicloud:write` 才能读取配置及该指南；表单本身不读取秘密配置、不调用 API。
Open `/alicloud` → **Cloud connections and operations** → SchedulerX3 **Configure** → **Guide** → **Connect scheduled tasks / Prepare cloud HTTP callback configuration**. The existing connection drawer requires `alicloud:write` to read its configuration and show this guide. The preparation form itself reads no secret configuration and calls no API.

**当前状态 / Current status:** `/alicloud?tab=scheduler-managed` 提供受管任务预览、已有 HTTP Job 的日历/重试修改、独立启停、原编号本地恢复及历史归档；Mock 可逐类创建六种停用声明。Live 新建 HTTP 执行器载荷合同尚未验证，接口会拒绝创建，需先在实际云控制台登记。`/alicloud?tab=scheduler-native` 用于完整观察与人工关联。已有六类执行体、认证 callback 和执行领取/去重，任务登记、观察与保存关联均不证明真实部署或业务执行成功。
Open `/alicloud?tab=scheduler-managed` for previews, calendar/retry changes to existing HTTP jobs, separate enable/disable, original-ID local recovery and history archive. Mock supports six disabled declarations. The Live HTTP creation payload contract remains unverified, so creation is rejected; register jobs in the actual cloud console first. Use `/alicloud?tab=scheduler-native` for complete observations and explicit local association. The six handlers, authenticated callbacks and claims/deduplication exist; registration, observation and saved bindings do not establish actual deployment or successful business execution.

受管页先明确保存来源、提交完整观察，再在 300 秒内采用当前观察与绑定版本。写入前审查预览并确认；回复不确定时保留原编号并 GET 读取。恢复只提交本地已知事实和审计，不能重放云请求。云启用也不会自动部署回调或修复已撤销的关联资格。
Save the source explicitly, submit a complete observation, then adopt the current observation and binding revision within 300 seconds. Review and confirm each write. Keep the original ID and GET it after an uncertain reply. Recovery commits known local facts and audit without replaying cloud requests. Cloud enable does not deploy callbacks or restore revoked binding qualification.

## 个人 / 单机部署 — Personal / single-host use

1. 保留 `AGF_SCHEDULER_BACKEND=local-cron`；本地日历按 UTC 执行，不需要云 HTTP 应用或云任务。
   Retain `AGF_SCHEDULER_BACKEND=local-cron`; local calendars use UTC and require no cloud HTTP app/jobs.
2. 部署设置 `AGF_SERVER_URL` 为主平台 API 地址，设置 `AGF_SCHEDULER_TENANT_ID` 为实际租户 UUID。业务请求使用该租户的专用服务 Key（部署 secret `AGF_SCHEDULER_API_KEY`），按下表授予权限。不要复制控制台登录 JWT 或使用另一个租户的 Key。
   Set `AGF_SERVER_URL` to the main platform API and `AGF_SCHEDULER_TENANT_ID` to its tenant UUID. Supply a same-tenant service key through deployment secret `AGF_SCHEDULER_API_KEY`, with the task permissions below. Do not copy a console JWT or another tenant's key.
3. 配置实际需要的规则、红队、报表、归档目录及文件权限；按业务需求启用任务。配置改变后重启 scheduler，不以控制台连接“保存”代替部署。
   Configure required rules, red-team, report/archive directories and filesystem access, then enable the needed tasks. Restart the scheduler after deployment changes. Saving a console cloud connection does not deploy these settings.
4. 使用数据库保留跨进程执行回执。数据库不可用时 local-cron 可以降为内存回执，重启后丢失；这不是持久去重保证。
   Use a database for persistent execution receipts. Local-cron can fall back to in-memory receipts without a database; they are lost on restart and provide no persistent deduplication guarantee.

## 企业云调度 — Enterprise cloud scheduling

1. 选择实际租户。已有连接设置保存 SchedulerX3 区域、`ClusterId`、`AppName` 和管理云任务的 RAM/STS 身份。保存配置只影响云 API 连接；不会注册任务或部署回调。
   Select the tenant. Save SchedulerX3 region, `ClusterId`, `AppName` and cloud RAM/STS identity in Connection settings. This changes the cloud API connection only; it does not register jobs or deploy callbacks.
2. 云控制台选择实际 HTTP 应用，记录其 **AppId**。AppName/ClusterId 是 OpenAPI 范围；AppId 是云 callback 身份，不能根据名称推断。
   Choose an actual HTTP app in the cloud console and record its **AppId**. AppName/ClusterId define OpenAPI scope; AppId identifies callbacks. Do not infer one from the other.
3. 准备云执行器可访问的 HTTPS 反向代理，转发到 scheduler 服务 `9101`。主平台 API（默认 `8080`）和云 OpenAPI endpoint 都不能代替这个入口。从实际云执行器网络验证 DNS/TLS/连通性。
   Expose a reachable HTTPS reverse proxy to scheduler port `9101`. The main platform API (default `8080`) and cloud OpenAPI endpoint are separate. Validate DNS, TLS and connectivity from the actual cloud executor network.
4. 在准备表单填 HTTPS **origin**（仅主机和可选端口）、实际 AppId，明确选择任务。租户 UUID 来自顶部当前租户；需要另一部署时先切租户。只能用 HTTPS，无用户名、密码、接口路径、查询或片段。表单不请求此地址，也不验证它的网络或身份。
   Enter the HTTPS **origin** (host and optional port only), actual AppId, and select tasks. The UUID comes from the selected tenant; switch tenants first for another deployment. Credentials, paths, query strings and fragments are rejected. The form contacts no address and verifies neither networking nor identity.
5. 生成并复制材料。复制失败时可以手动选中材料复制。`requiredSecretReferences` 是要求，不是可运行的 token。材料无真实 Key/令牌；不要把真实秘密粘贴到 AppId、URL、报告或任务日志。
   Generate and copy the material, or select it manually if clipboard access fails. `requiredSecretReferences` is a requirement, not an executable token. The material contains no actual key/token. Never paste secrets into AppId, URLs, reports or job logs.
6. 部署管理员从 secret 管理系统提供以下值，配置数据库，设置后端并重启。不要把此表复制成含真实秘密的 shell 示例。
   The deployment administrator supplies the following values from secret management, configures the database and restarts. Do not turn this table into a shell example containing actual secrets.

| 部署项 / Deployment item | 实际来源 / Actual source |
|---|---|
| `AGF_SCHEDULER_BACKEND=schedulerx3` | 仅切换 scheduler 六类本地周期 / Switches these six scheduler timers only |
| `AGF_SERVER_URL` | 主平台 API 地址 / Main platform API address |
| `AGF_SCHEDULER_TENANT_ID` | 当前实际租户 UUID，不是 slug / Actual tenant UUID, not slug |
| `AGF_SCHEDULER_API_KEY` | 同租户服务 Key secret；执行下表业务 / Same-tenant service-key secret; executes the operations below |
| `AGF_SCHEDULER_CALLBACK_TOKEN` | 独立 32–256 字节 secret；认证云 HTTP callback / Separate 32–256 byte secret; authenticates cloud callbacks |
| `AGF_SCHEDULER_CALLBACK_APP_ID` | 实际云 HTTP AppId，规范正 int64 字符串，最大 9223372036854775807 / Actual canonical positive int64 HTTP AppId string |
| 数据库和任务目录 / Database and directories | 云模式要求数据库；主服务应先完成迁移 / Cloud mode requires a database; complete main-service migrations first |

7. 云控制台按真实 HTTP 执行器 UI 配置每条任务：POST 对应 callback URL；Authorization 为 `Bearer ` 加部署回调 secret。云提供 `schedulerx-appId`、正数 `schedulerx-jobId`、`schedulerx-jobExecutionId`。不要用示例数字冒充真实身份，不把平台服务 Key 当 callback token。
   Configure each HTTP job in the cloud console: POST to its callback URL; Authorization is `Bearer ` plus the deployed callback secret. The cloud supplies `schedulerx-appId`, positive `schedulerx-jobId`, and `schedulerx-jobExecutionId`. Example numbers are not proof of identity. The platform service key is not the callback token.
8. 配置实际日历、时区、超时和依赖。生成材料不是 CreateJob JSON：当前 HTTP 执行器参数载体没有原生控制台合同，不能把本地 UTC cron/本地任务 UUID 当云 Quartz/真实 JobId。登记后分别核对真实 JobId、云回读、执行器回执与业务结果。
   Set actual calendars, timezone, timeout and dependencies. Generated material is not CreateJob JSON: no native console contract defines the HTTP executor parameter carrier. Local UTC cron/local UUIDs are not cloud Quartz/JobIds. Verify actual JobIds, cloud readback, callback receipts and business outputs separately.

启动云模式前，在原生观察页明确观察实际 HTTP 任务，并整体采用六类所需关联；确认每项资格可用。保存关联不会自动注册云任务，已有云任务仍按真实执行器手动配置。具体操作与原执行恢复见 [云回调执行指南](scheduler-callback-execution-guide.md)。
Before starting cloud mode, explicitly observe actual HTTP jobs and adopt the needed task associations in the native panel. Check each item's eligibility. Local associations do not register cloud jobs; configure existing cloud jobs in their actual executor. See the linked callback execution guide.

## 六类任务 — Six actual task kinds

以下权限属于部署平台服务 Key，云 RAM 权限或当前登录角色不能替代它。云绑定六类任务都需要 `alicloud:read`，再加下表各任务权限。每次 callback 检查当前原服务 Key、租户、来源和可信采用资格；各业务请求继续检查权限。
The permissions below belong to the deployed platform service key. Cloud RAM permissions or the logged-in role do not replace it. Every cloud-bound task requires `alicloud:read` plus its task grants below. Each callback checks the current original service key, tenant, source and trusted adoption eligibility; business APIs also enforce their own grants.

部署任务开关缺省 `true`，明确填 `true/false` 后重启 scheduler；回调 alias `report`/`archive` 的部署名称不同，不要猜变量名：
Deployment task flags default to `true`; set `true/false` and restart. The `report`/`archive` callback aliases have different runtime names:

| callback kind | 部署开关 / Deployment flag |
|---|---|
| asset-inventory | `AGF_SCHEDULER_ASSET_INVENTORY_ENABLED` |
| log-pull | `AGF_SCHEDULER_LOG_PULL_ENABLED` |
| redteam-cruise | `AGF_SCHEDULER_REDTEAM_CRUISE_ENABLED` |
| rule-hot-reload | `AGF_SCHEDULER_RULE_HOT_RELOAD_ENABLED` |
| report | `AGF_SCHEDULER_REPORT_GENERATE_ENABLED` |
| archive | `AGF_SCHEDULER_COLD_ARCHIVE_ENABLED` |

勾选准备表单只决定复制材料包含哪些 URL，不改变这些开关，也不修改其它任务的启用状态。
The form selection only determines which URLs appear in the copied material. It changes none of these flags or other task enablement.

| callback kind | 目标与准备 / Target and preparation | 验收 / Verification |
|---|---|---|
| `asset-inventory` | 默认已有资产统计，`assets:read`。可选 AgentTeams 完整同步另需 `alicloud:write`、`assets:write`，已启用连接及手动同步；设置 `AGF_SCHEDULER_AGENTTEAMS_SYNC_ENABLED=true`，真实连接另需 `AGF_SCHEDULER_AGENTTEAMS_CONFIRM_LIVE=true` / Existing statistics by default; explicit AgentTeams sync requires the additional permissions, enabled connection, manual sync and flags | 统计 JSON；同步启用时再检查回执/台账 / Statistics JSON, plus receipt/inventory if syncing |
| `log-pull` | 所有启用且到期 HTTP Pull 源；`sources:read`、`sources:write`，接入管理先保存/启用；没有任意 source-ID 选择器 / All enabled due HTTP Pull sources; configure sources first, no arbitrary source-ID selector | accepted/skipped/failed 与日志查询 / Counts and log queries |
| `redteam-cruise` | 平台用例和 `scheduler-local-simulator`；`redteam:read`、`redteam:execute`；`AGF_SCHEDULER_REDTEAM_GUARD` 0–100，可写红队目录 / Platform cases and offline simulator, guard 0–100 and writable directory | campaign ID、证据、JSON 和 Markdown；不是 Live 攻击/CI / Campaign, evidence, JSON and Markdown; not live attacks/CI |
| `rule-hot-reload` | `policies:write`；合法 `AGF_RULES_DIR`，检查目录后请求平台重载已保存策略 / Valid rules directory, then reload saved platform policies | reloaded/total；不上传本地规则正文、不表示 MSE/APIG 发布或消费者热载 / No local-rule upload, MSE/APIG publication or consumer-load claim |
| `report` | `reports:write`，有效同租户服务身份；读取部署规则/红队/统计/归档目录，写 Markdown / `reports:write`, valid same-tenant identity and deployment directories; writes Markdown | 实际文件；不是业务 PDF/CSV/通知计划 / Actual file, not business PDF/CSV/notification plans |
| `archive` | `reports:write`，有效同租户服务身份；报表目录超龄文件 gzip，对象存储或本地降级；`AGF_SCHEDULER_ARCHIVE_AFTER_DAYS`，`AGF_SCHEDULER_ARCHIVE_DELETE_LOCAL` 默认 false / `reports:write`, old report files, object storage or local degradation; configured age, deletion defaults to false | SHA256、uploaded/local/degraded/failed；不是事件 Parquet 或云日志清理 / Hash and true outcome, not event Parquet/cloud-log cleanup |

## 分片、顺序、结果 — Partitions, order and outcomes

- 日志源、红队用例和归档文件按稳定资源分片。实际 executor 支持时可广播；`schedulerx-shardingindex` 与 `schedulerx-shardingtotal` 成对，index 从 0，总数 1–256；同批次不能变 total。`asset-inventory`、`rule-hot-reload`、`report` 须 `total=1`；其它分片会跳过，无法满足下游完整成功条件。旧资产任务默认 4 片的云配置需明确改成单片并用新批次验收。
  Logs, cases and archives use stable resource partitions. Broadcast only when the actual executor supports it; index/total headers must be paired, index starts at 0 and total is 1–256. Keep totals fixed. Set total=1 for asset-inventory, rule-hot-reload and report; other partitions skip and cannot satisfy full-success dependencies. Explicitly update older four-partition asset jobs and verify a new batch.
- 依赖为 `asset-inventory → log-pull`、`asset-inventory → redteam-cruise`、`asset-inventory + log-pull → report → archive`；rule-hot-reload 无上游。最近上游批次须所有分片在 24 小时内成功。本地补跑上游，云 callback 只等待，不自动注册工作流。
  Dependencies are asset → logs; asset → red-team; asset + logs → report → archive. Reload has none. All shards of the latest upstream batch must succeed within 24 hours. Local execution fills dependencies; cloud callbacks wait and do not register workflows.
- 单次 callback 成功必须 HTTP 200 且 `ok=true`。保留实际云 executionId；同 ID/分片成功可复用。失败、降级、跳过、不确定分别核查，不显示“全部已接入”。超时或租约过期的 running 禁盲目重发；先查原回执与业务事实。
  Callback success requires HTTP 200 and `ok=true`. Retain actual execution IDs. Successful same-ID/shard results may be reused. Check failed/degraded/skipped/uncertain outcomes individually. Read the original receipt and reconcile actual business effects after timeout or lease expiry. Never redispatch the original execution identity.
- `local-cron` 旧执行回执每 kind 最多 2048 条、非 running 最长 30 天。云模式使用独立的永久 Fact/Batch/Request 身份，不经过旧重试通道；纯 GET 不启动、续租或修复。永久身份不能保证所有外部系统恰好一次。轮换 Key 前核对未完成事实；新 Key 不能接管旧事实。
  Legacy local-cron receipts are bounded to 2048 per kind and 30 days for non-running rows. Cloud mode uses permanent Fact/Batch/Request identity and bypasses the legacy retry lane; pure GET never starts, renews or repairs work. This does not guarantee external exactly-once effects. Reconcile unfinished facts before key rotation; a new key cannot take over old facts.
- `/tasks` 是 scheduler 部署诊断，检查实际 backend/持久回执/最近结果；不要直接向公网暴露。`implemented`、ready 或某个 JobId 都不证明六任务已登记/执行。
  `/tasks` is scheduler deployment diagnostics. Inspect backend, persistence and results without exposing it publicly. Implemented/ready or a JobId does not prove registration/execution.
- `schedulerx3` 只停止这六类 scheduler 本地周期。主服务 HTTP Pull 到期扫描、业务报表计划、每日资产快照仍独立运行，云触发继续遵守业务 due/lease，不是接管全部 timers。
  schedulerx3 stops these six local scheduler timers only. Main-service due-source scanning, business report plans and daily asset snapshots remain independent; cloud triggers still respect due/lease rules.

切换租户/登录会话会清空表单与材料；同会话 token 刷新不清空。不要把复制成功当作部署、连通性或云登记成功。
Tenant/sign-in changes clear drafts/material; a same-session token refresh does not. Successful clipboard copying is not deployment, connectivity or registration success.
