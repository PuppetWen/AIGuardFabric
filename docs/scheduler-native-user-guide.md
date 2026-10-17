# SchedulerX3 原生观察与本地关联

入口：阿里云协同页面的“Scheduler 任务接入”：`/alicloud?tab=scheduler-native`。

本功能读取云端真实应用和任务，保存平台本地关联。当前 `callbackBindingEnforced=false`；云任务注册、部署、回调配置与网络可达性未知。保存成功不能证明六类任务已经运行，也不会启停云任务或控制服务的所有 timer。

## 权限与来源配置

- 查看、手动观察、原编号读取和分页：`alicloud:read`。
- 明确初始化隔离 Mock 示例、替换/停用本地关联、正文归档：另需 `alicloud:write`。
- 在阿里云协同连接表中配置 **SchedulerX3 / `alicloud-schedulerx3`**。明确填写 `region_id`、`cluster_id`、`app_name`、RPC 地址、模式和启用状态；真实云按连接指南提供 RAM 凭据。`account_id` 只是来源标签，不证明云账号身份。
- 此页面不显示、保存或复制 AccessToken、任务 HTTP 正文、脚本或凭据。观察中的存在性/摘要不证明回调正确。

## 观察、关联与冲突恢复

1. 保存来源配置，再进入此页。初次 GET 仅读取平台状态，不会读云、初始化示例或注册任务。
2. 手动发起新观察。真实云须勾选读取确认；Mock 初始化需独立勾选且有写权限，不自动初始化。每次新观察创建新 UUID。

   隔离 Mock 示例只支持 `region_id=cn-hangzhou`、`cluster_id=cluster-agf-demo`、`app_name=app-agf-demo`。手动保存 Mock 来源再明确初始化。6 条示例记录只有 1 条启用 HTTP 任务，其余停用、非 HTTP 或未知；不能据此宣称六任务全部绑定或可运行。
3. 保存原 UUID。超时或失败先读取该 UUID；分页仅 GET 同一份观察，不重派。最多 20 个云分页、2,000 个任务。完整遍历不是强云快照。失败或归档没有正文不能解释为零任务。
4. 完整观察完成后 300 秒内，明确采用最新本地关联版本与所读观察。这个时限是人工采用门槛，不是保存后的每日/月度任务授权有效期。
5. 逐页把启用的 HTTP JobId 指派给平台任务。ID 按字符串保存，超过 JavaScript 精确整数范围也不截断。不会按名称自动匹配，一个 JobId 只能对应一种平台任务；跨页草稿保留。
6. 检查下表真实目标与部署配置，确认整体替换，再确认保存。空列表明确清空本地关联；保存不创建或修改任何云任务。可部分关联，不能据此称六项全部完成。
7. 409/412/400/401 后保留草稿和操作编号。重新加载只比较当前状态，不更新草稿基线或自动重发。先核查来源、任务资格、观察时间和最新版本，再明确采用并手动提交新意图。网络失败时先核对当前关联，避免重复意图。
8. 停用只改变本地关联；云任务和部署服务仍可能运行，须分别由管理员处理。配置停用后仍可读取历史回执及按权限归档。

## 逐任务资格与采用证明

“已保存的逐任务资格”显示当前 CAS 版本、原采用版本（`adoptionVersion`）、来源是否仍一致与每项 `eligible / revoked / unverified`。总体 `current=false` 不表示所有 Job 都失去资格：部分关联可同时包含仍合格与已撤销的项。来源版本变化另显示 stale，不能静默改用新来源。

点击某项“查看资格证据”，分别核对原始采用证明、决定观察编号/时间、最近完整存储证据。它们是独立事实；读取证据只使用 GET，不读云或自动改关联。旧记录没有可信证明时显示 `unverified / proof_unavailable`，不能凭新正面证据自动获得资格。

完整新观察发现 AppId 改变、所选 Job 缺失、明确停用或已知非 HTTP 类型时，该项变为 `revoked`；未知类型或未知启用状态为 `unverified`。失败或不完整观察不作为负面证明。原因分别显示 `app_changed`、`job_missing`、`job_disabled`、`job_not_http`、`job_type_unknown`、`job_status_unknown`。

即使最近完整证据又显示启用 HTTP Job，已撤销或未验证资格也不会自动恢复，原负面决定保留。先手动发起新完整观察，再在完成后 300 秒内明确采用最新 CAS 版本与观察，核查草稿并确认保存新的替换意图。重新加载仅比较，不自动采用或 POST。

300 秒只限制人工采用观察；已保存资格不会因观察变旧而过期。归档原观察正文保留自包含的原采用证明、资格与永久事实，不能当作停用本地关联；需要停用时另做明确操作。上述资格仍只是本地可信证据，`callbackBindingEnforced=false`，不证明当前云启用、云注册、部署或执行。

## 六类任务的真实含义

| 公共 kind | 实际 runtimeName | 当前目标与必要配置 |
| --- | --- | --- |
| `asset-inventory` | `asset-inventory` | 默认统计现有资产（`assets:read`），不发现新资源。可明确启用 AgentTeams 完整同步，另需 `alicloud:write`、`assets:write`、已启用连接和先成功手动同步；部署明确配置同步/Live 确认开关。 |
| `log-pull` | `log-pull` | 本租户所有启用且到期 HTTP Pull 源，需 `sources:read/write`，使用平台持久游标和解析器；源身份不放进云任务。 |
| `redteam-cruise` | `redteam-cruise` | 固定 `scheduler-local-simulator` 离线模拟，需 `redteam:read/execute`；部署强度与可写红队目录。当前不执行真实目标攻击或 CI gate。 |
| `rule-hot-reload` | `rule-hot-reload` | 校验 `AGF_RULES_DIR` 后重载平台策略，需 `policies:write`；不上传规则正文，不发布 MSE/APIG，也不证明外部消费者热载。 |
| `report` | `report-generate` | 汇总部署规则、红队、统计和归档目录，生成 Markdown；需真实服务身份和目录权限，不是控制台 PDF/CSV 或通知计划。 |
| `archive` | `cold-archive` | 处理超龄报表文件，上传对象存储或明确降级为本地 gzip；配置对象存储身份、目录、归档期限，删除本地默认 false。不清理事件库或云日志。 |

## 企业与个人部署

企业管理员应单独部署 scheduler 服务，设置实际租户 UUID、同租户平台服务身份、云应用 AppID、独立 callback token 的 Secret 引用、可达 HTTPS 回调、各类任务目录与依赖。平台 API Key、云 RAM 身份和 callback token 是不同身份。敏感值只通过部署的 Secret 系统注入，不进入此表单、SQL 关联或 API 回执。

个人单机也需分别运行 API 与 scheduler 服务，配置本机目录权限并核验云端可达入口。LAN 地址不会自动成为云回调地址。现有准备向导：[Scheduler 注册准备操作指南](scheduler-registration-user-guide.md)；服务配置详见 [Scheduler 指南](scheduler-guide.md)。准备配置或 `/tasks` 诊断不证明云注册成功。服务 timer 与真实回调应分别验证；以实际 JobExecutionId、平台回执和真实产物确认执行。

## 容量与归档

列表仅显示最近 50 条正文记录；已知旧 UUID 可直接读取。最多保留 128 份观察正文、64 MiB 聚合存储，每次明确归档不超过 100 条。确认数量与当前台账代次，CAS 冲突后重新加载比较再复核选择。归档移除分页正文，永久原事实/编号保留，旧编号不会重派；它不代表云端工作停止，也不等同撤销保存的本地关联。需要撤销关联时单独停用。

过期租约的 `interrupted` 是本地状态，不能证明远端取消。配置了数据库才支持持久跨实例事实；未配置数据库时仅保留在当前进程。

## English steps

The native page reads cloud applications/jobs and saves **local associations**. `callbackBindingEnforced=false`; registration, deployment, callback configuration and reachability remain unknown. A successful association is not proof that six jobs run.

1. With `alicloud:read`, view local state, manually observe, and read/paginate original receipts. Add `alicloud:write` for explicit Mock initialization, replacement/disable and body archive.
2. Save and enable the `alicloud-schedulerx3` connection with explicit region, cluster, application, RPC origin, mode and live credentials. A configured account label is not verified identity. GET never reads cloud or initializes a fixture.
3. Explicitly observe with a new UUID and Live confirmation where required. After failure, read the original UUID before another observation. Paging reads one stored snapshot. The 2,000-job/20-page traversal is complete but not a strong cloud snapshot.

   The isolated Mock fixture accepts only `region_id=cn-hangzhou`, `cluster_id=cluster-agf-demo` and `app_name=app-agf-demo`; save it explicitly before initialization. Its six observed records contain only one enabled HTTP job, so it cannot prove six bindings or runnable tasks.
4. Within 300 seconds of a completed current observation, explicitly adopt it and the latest local binding version. Select enabled HTTP jobs across pages; string IDs retain int64 precision. Names do not imply bindings. Review the task/runtime table above and the existing [registration preparation guide](scheduler-registration-user-guide.md).
5. Confirm full local replacement; an empty list clears associations. A 4XX keeps the draft. Reload compares without adopting or automatically resubmitting; adopt deliberately before a new manual intent. Local disable stops neither cloud jobs nor deployed services.
6. Enterprise administrators separately deploy the scheduler with the real tenant UUID, same-tenant service identity, AppID, independent callback-token **Secret reference**, HTTPS ingress and task-specific directories/dependencies. Personal installations also run API and scheduler separately; LAN reachability does not prove cloud reachability. No secret values are stored here. `/tasks` is diagnostic only. Verify service timers separately using actual execution IDs, receipts and artifacts.
7. Archive only after explicit count/generation review. Up to 100 bodies are removed; permanent facts and original IDs remain. Archive does not cancel cloud work or disable saved associations. Expired leases mean local interruption. Cross-instance durability requires a database.

### Review per-job qualification

“Saved per-job qualifications” separates current CAS revision from the original adoption revision, source/version matching and each item’s `eligible / revoked / unverified` status. Overall `current=false` does not make every item unavailable. Changed sources stay stale until explicitly replaced.

Open “View qualification evidence” to compare the original adoption proof, decision observation/time and latest complete stored evidence. Reading any original ID uses GET only; it neither reads cloud nor changes qualification. Legacy records without a proof are `unverified / proof_unavailable`.

A complete new observation can revoke an item for `app_changed`, `job_missing`, `job_disabled` or `job_not_http`; unknown type/status yields `job_type_unknown` or `job_status_unknown` and unverified qualification. Failed/incomplete observations are not negative proof. Later positive evidence does not restore revoked/unverified qualification or replace its original decision automatically. Explicitly observe again, adopt the latest CAS version and fresh observation, then confirm a new local replacement. Reload preserves the draft and never POSTs automatically.

The 300-second window limits human adoption, not the lifetime of a saved qualification. Archiving the original body retains its self-contained adoption proof, qualification and permanent fact; disabling an association is a separate explicit operation. These local proofs do not establish cloud enablement, registration, deployment or execution; `callbackBindingEnforced` remains false.
