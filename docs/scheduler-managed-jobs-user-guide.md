# SchedulerX3 受管六任务 / Managed six SchedulerX3 jobs

本指南对应独立 `SchedulerManagedJobsPanel` 和 `/api/v1/alicloud/schedulerx3/native/jobs` 八项合同。页面挂接与实际运行门禁由集成阶段完成；候选定义不等于已部署。读取入口只 GET，不初始化、不注册、不隐式启用任务。
This guide describes the independent panel and its eight API operations. Entry registration and actual execution gates belong to integration; a candidate is not a deployment. Opening the page performs GET only, without initialization, registration or implicit enable.

查看需要 `alicloud:read`；受管预览/修改/恢复/归档需要管理员 **User** 及 `platform:admin`、`alicloud:read/write`。API Key 不可管理。配置停用不阻挡原回执读取或服务端许可的纯本地恢复/归档。
Read requires `alicloud:read`. Management requires an administrator **User** with `platform:admin` and `alicloud:read/write`; API Keys cannot manage. Disabled configuration does not block original receipt reads or server-permitted local recovery/archive.

## 1. 明确来源 / Explicit source

在 `/alicloud` 云连接区选择 SchedulerX3 → 配置，手工保存 `region_id`、`cluster_id`、`app_name`、RPC 根地址及模式。真实云凭据在连接设置管理；`account_id` 只是标签，不能证明账号身份。保存来源不部署 scheduler，不切换生产后端。
In cloud connections choose SchedulerX3 → Configure, then manually save `region_id`, `cluster_id`, `app_name`, RPC origin and mode. Manage live credentials there; `account_id` is a label, not proof of account identity. Saving a source neither deploys the scheduler nor switches the production backend.

隔离 Mock 示例仅 `cn-hangzhou / cluster-agf-demo / app-agf-demo`。手工保存后明确勾选初始化，再人工提交完整观察。GET 不种示例。原示例并不是六条启用 HTTP Job；创建声明后仍停用，HTTP carrier 是否可部署/执行未知。
The isolated Mock fixture supports only `cn-hangzhou / cluster-agf-demo / app-agf-demo`. Save it manually, explicitly initialize, then submit a complete observation. GET never seeds it. The original fixture does not have six enabled HTTP jobs; new declarations remain disabled with unknown carrier deployment/execution.

## 2. 观察、选择、采用 / Observe, select and adopt

- 手工发起新编号观察；Live 单独确认只读云请求，typed loopback 测试不显示为 Live。失败读取本次原 UUID，不自动重复 POST。
  Manually observe with a new ID. Confirm a live cloud read separately; a typed loopback test is not Live. Read the original UUID after failure; POST is never automatically repeated.
- 原观察回执分页只 GET，每页 50；新观察返回的初始页可能 100。Job/App ID 按正 int64 字符串保存，跨页选择保留，不按名字推断。
  Original receipt pages use GET with 50 rows; a new observation's initial page may contain 100. Job/App IDs remain positive int64 strings. Cross-page choices persist; names never imply identity.
- 完整观察完成后 300 秒内，明确采用观察和当前绑定版本。刷新只比较，409/412 保留草稿及旧 CAS 基线。新观察后旧选择仍显示，但需在新证据中重新核实并选择该 Job。
  Explicitly adopt the complete observation/current binding revision within 300 seconds of completion. Reload compares only; 409/412 keep the draft and old CAS base. After a new observation the old selection remains visible, but verify/select that job in the new evidence.

300 秒是人工采用门槛，不是持久绑定的运行有效期。来源、模式、完整 fingerprint、配置版本与绑定 CAS 在服务器当前事务再次校验；页面可用按钮不是执行授权。
The 300 seconds are a human-adoption window, not a saved binding runtime TTL. The server rechecks source, mode, full fingerprint, configuration revision and binding CAS in the current transaction. An enabled UI button is not execution authority.

## 3. 每次一个明确动作 / One explicit action per intent

| 动作 / Action | 范围 / Scope |
|---|---|
| `create_disabled` | 仅 Mock，明确名称、六类 kind、日历/时区/重试；`total=1`，始终停用 / Mock only, explicit name/kind/calendar/timezone/retry, `total=1`, always disabled |
| `update_schedule` | 已观察并明确停用的 HTTP Job，只改勾选字段 / Observed explicitly disabled HTTP job, checked fields only |
| `disable` | 已观察启用 HTTP Job，独立单次停用 / Observed enabled HTTP job, one separate disable |
| `enable` | 已观察停用 HTTP Job，独立单次启用 / Observed disabled HTTP job, one separate enable |

日历/表达式最多 256 UTF-8 字节，时区最多 64，名称最多 200；值不悄悄 trim。明确空日历表示清空，未勾选表示保留。时间类型 `-1/1/3/5/100`，重试次数 `0..1000`，间隔 `0..86400`。新建必须明确时间类型、非空时区、重试和间隔，定时类型还需表达式。
Calendar/expression are bounded at 256 UTF-8 bytes, timezone at 64 and name at 200; values are never silently trimmed. Explicit empty calendar clears it; unchecked means preserve. Time types are `-1/1/3/5/100`, attempts `0..1000`, interval `0..86400`. Creation requires explicit time type, nonempty timezone, attempts/interval and an expression for scheduled types.

Live 的 HTTP `JobHandler`/`XAttrs` 创建载体没有可信合同，新建严格拒绝 412。已有 HTTP Job 可以保存受管日历/重试，其他字段保留；启用中的 Job 必须先单独停用、重新完整观察，再修改。修改不会顺带启用、绑定或部署。
The Live HTTP `JobHandler`/`XAttrs` creation carrier lacks a trusted contract and creation is rejected with 412. Manage calendars/retry on existing HTTP jobs while preserving other fields. Disable an enabled job separately, observe completely again, then update. Update never implicitly enables, binds or deploys.

## 4. 预览与原编号恢复 / Preview and original-ID recovery

核对旧值/新值，明确确认无云 CAS、回调未强制执行、部署/消费者未知；Live 写单独确认。每个预览只尝试一次新请求 UUID。回包丢失、408/5xx、不可信 2xx 时保留原 body/UUID 并锁写；GET 原回执，404 也不能解锁重复提交。
Review old/new values and confirm no cloud CAS, unenforced callbacks and unknown deployment/consumers; confirm Live writes separately. Attempt each preview once with a new request UUID. Lost responses, 408/5xx or invalid 2xx retain the original body/UUID and lock writes. GET the original receipt; 404 never unlocks redispatch.

`Accepted` 是原写结果，`Matched/Different/Unknown` 是独立读回；匹配不会将旧写 Unknown 升级成功。`pending_audit` 或过期 `started` 按服务端动作显式本地恢复，只结束原事实和唯一审计，不联系 provider。停用或改版来源也可读原回执；原来源不改写成新配置。
`Accepted` is the original write result; `Matched/Different/Unknown` describe independent readback. A match never upgrades an Unknown write. Explicit server-permitted recovery of `pending_audit` or expired `started` completes the original local fact/unique audit without a provider call. Read old receipts after source disable/change; the original source is never rewritten as current configuration.

同租户、集群和应用的旧 Unknown 是保守资源风险围栏，改账号标签、端点、区域、凭据或模式不能绕开。先本地结束旧事实，等原租约后完成新观察，并明确接受独立新写重叠风险。不能证明旧远端已停止。
An older Unknown for the same tenant, cluster and app is a conservative resource fence. Changing account labels, endpoint, region, credentials or mode cannot bypass it. End the old local fact, complete a new observation after its lease, then accept new-write overlap explicitly. This does not prove old remote work stopped.

## 5. 六类真实目标与部署 / Six actual targets and deployment

| Kind | Runtime |
|---|---|
| `asset-inventory` | `asset-inventory` |
| `log-pull` | `log-pull` |
| `redteam-cruise` | `redteam-cruise` |
| `rule-hot-reload` | `rule-hot-reload` |
| `report` | `report-generate` |
| `archive` | `cold-archive` |

任务真实目标、部署开关、权限和产物见 [注册准备指南](scheduler-registration-user-guide.md) 与 [回调执行指南](scheduler-callback-execution-guide.md)。创建或启用 Job 后，去 [原生观察与关联指南](scheduler-native-user-guide.md) 人工重新观察/采用/保存关系。负面资格不会因再次启用自动恢复。
See the linked registration/callback guides for actual targets, deployment flags, grants and artifacts. After creating/enabling a job, explicitly observe/adopt/save relationships in the native panel. Negative qualification never restores automatically on enable.

企业部署独立配置实际租户 UUID、AppID、服务 Key、独立 callback token Secret 引用、可达 HTTPS→scheduler `9101` 与任务目录；个人单机分别运行 API/scheduler，可保留 `local-cron`。默认单机 `total=1`；K8s 广播只按真实执行器能力/固定分片数部署，汇总任务不能假造广播。不要把主 API `8080` 或 RPC endpoint 当 callback 地址，不把真实 token 粘贴到名称/报告。
Enterprise deployment separately configures the actual tenant UUID, AppID, service key, independent callback-token secret reference, reachable HTTPS→scheduler `9101` and task directories. Personal installs run API/scheduler separately and can retain `local-cron`. Default total is 1; deploy K8s broadcasts only under real executor capabilities/fixed shard totals, never as invented summary broadcasts. Main API `8080`/RPC origins are not callback addresses; never paste actual tokens into names/reports.

本工作流明确 `callbackBindingEnforced=false`、部署/回调配置/消费者为 unknown、云 CAS 不存在；不声称云激活或六类任务已经执行。Phase2 真实云凭据/设备验收未授权。服务 timer 与 callback 分别核查，`/tasks` 仅诊断，不是云注册证据。
This workflow states `callbackBindingEnforced=false`, unknown deployment/callback configuration/consumers and no cloud CAS. It claims neither cloud activation nor execution of all six tasks. Phase2 real-cloud credentials/device acceptance is unauthorized. Verify service timers and callbacks separately; `/tasks` is diagnostic, not registration evidence.

## 6. 正文容量和归档 / Body capacity and archive

每类最多 128 份正文，总计 64 MiB；列表每类最新 50 条，不无限扫，旧 UUID 单独 GET。最多一次归档 48 条，必须选择服务器允许的非活动终态或过期未领取预览，审查代次/数量并确认不可恢复的正文损失。冲突保留选择，重新审查才采用新代次。
There are at most 128 bodies per class and 64 MiB total. Lists show each class's latest 50 without an unbounded scan; GET an older UUID separately. Archive at most 48 server-eligible inactive terminal records or expired unclaimed previews. Review generation/count and confirm irreversible body loss. A conflict keeps choices; re-review explicitly adopts the new generation.

归档释放旧值/新值/预览正文，保留永久 UUID、原结果、风险围栏，绝不重派旧编号，也不停止远端。数据库才提供持久跨实例去重和恢复；无数据库仅当前进程的 Mock 状态，Live 修改要求数据库。
Archive releases old/new/preview bodies, retains permanent UUIDs/results/risk fences, never redispatches an old ID or stops remote work. Durable cross-instance dedup/recovery require a database. Without one Mock state lasts for this process; Live modification requires a database.
