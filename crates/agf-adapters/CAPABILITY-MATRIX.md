# agf-adapters 能力矩阵（`send` / `push` / `pull` / `sync`）

> 本文件由 `agf_adapters::vendors::capability_matrix::capability_table_markdown()` 渲染，
> 与代码同源（`metadata().semantics` 是唯一真源）：
>
> ```
> cargo test -p agf-adapters --lib capability_table_renders_and_prints_for_docs -- --nocapture
> ```
>
> "是否真测"一列引用的集成测试函数名由单测 `evidence_tests_exist_in_wiremock_suite` **逐条核对存在性**
> （测试源码经 `include_str!` 编译期嵌入），因此矩阵不能"声称已测但没测"。
>
> `Unsupported` 一律给出**协议/权限层面的客观原因**，并且运行时返回**不可重试**的
> `DomainError::Validation`（带同一条原因）——不是 `NotImplemented` 占位。
> 有单测守住：12 个内置适配器的 36 条语义 = 13 条已实现 + 23 条 `Unsupported`，且不得出现
> "尚未实现/TODO"字样。

| 适配器 | send | push | pull | sync | 是否真测 | 证据 |
|---|---|---|---|---|---|---|
| `feishu` | ✅ 已实现 | ⛔ Unsupported：群机器人 Webhook 只有「投递」权限，没有消息更新/撤回接口（飞书更新消息需 tenant_access_token、钉钉撤回需企业内部应用 access_token + robotCode、企业微信撤回需应用 secret），本适配器未配置该类通道 | ⛔ Unsupported：通知渠道是单向投递（Webhook 无读取接口），没有「拉取外部状态」的语义 | ⛔ Unsupported：对账需要读回外部状态，通知渠道无读取语义，因此双向对账不适用 | 否 | 未测（push/pull/sync 均 Unsupported；send 见 `tests/http_vendors/retry_once.rs`） |
| `dingtalk` | ✅ 已实现 | ⛔ Unsupported：同上（群机器人 Webhook 无更新/撤回接口） | ⛔ Unsupported：同上（无读取接口） | ⛔ Unsupported：同上 | 否 | 未测（同 feishu） |
| `wecom` | ✅ 已实现 | ⛔ Unsupported：同上 | ⛔ Unsupported：同上 | ⛔ Unsupported：同上 | 否 | 未测（send 见 `tests/http_vendors/wecom_posts_markdown_and_reads_errcode.rs`） |
| `email` | ✅ 已实现 | ⛔ Unsupported：SMTP 是投递协议，没有「更新/撤回已投递邮件」的语义（重发 = 再调用一次 `send`，不属于状态回写） | ⛔ Unsupported：SMTP 只有投递方向（收取需 IMAP/POP3，本适配器未配置该类通道），无读取语义 | ⛔ Unsupported：同上 | 否 | 未测（send 见 `tests/email_smtp/impl_smtp_behavior.rs`） |
| `webhook` | ✅ 已实现 | ⛔ Unsupported：通用 Webhook 的接收方协议由使用方自定义，平台无法假设其存在「按对象 id 回写」的接口；需要回写的目标请新增专用适配器（如 jira/servicenow/edr） | ⛔ Unsupported：通知渠道是单向投递（无读取接口） | ⛔ Unsupported：无读取语义 ⇒ 双向对账不适用 | 否 | 未测 |
| `slack` | ✅ 已实现 | ✅ 已实现（`chat.update` 更新、`chat.delete` 撤回；需可选凭据 `bot_token`） | ⛔ Unsupported：Slack Web API 可更新消息但本适配器只做消息维度回写；拉取频道历史属于 `conversation.*` 域，不在对账语义内 | ⛔ Unsupported：消息更新是单向回写，无对账所需的外部读取语义 | 是 | `tests/http_vendors/semantics_edr_notify.rs#slack_push_updates_message_via_chat_update`、`#slack_push_revoke_deletes_message_and_reports_business_error` |
| `jira` | ✅ 已实现 | ✅ 已实现（`PUT .../transitions` 工作流推进 + `POST .../comment` 评论） | ✅ 已实现（`GET /rest/api/2/search`，JQL `updated >= since`） | ✅ 已实现（拉取 → 比对本地案件 → 按冲突策略回写） | 是 | `tests/http_vendors/semantics_push_pull.rs#jira_push_posts_transition_then_comment_with_exact_method_path_and_body`、`#jira_pull_searches_incrementally_with_jql_and_normalizes_items`、`tests/http_vendors/semantics_sync.rs#jira_sync_reconciles_with_external_wins_then_local_wins` |
| `servicenow` | ✅ 已实现 | ✅ 已实现（`PATCH /api/now/table/{table}/{sys_id}`） | ✅ 已实现（`sysparm_query=sys_updated_on>=cursor^ORDERBYsys_updated_on`） | ✅ 已实现 | 是 | `tests/http_vendors/semantics_push_pull.rs#servicenow_push_patches_incident_with_state_and_work_notes`、`#servicenow_pull_queries_incremental_incidents_by_sys_updated_on`、`tests/http_vendors/semantics_sync.rs#servicenow_sync_reconciles_local_case_conflicts` |
| `zentao` | ✅ 已实现 | ✅ 已实现（`PUT /api.php/v1/bugs/{id}`） | ✅ 已实现（`GET /api.php/v1/bugs?product=..&limit=..` + 客户端 `since` 过滤） | ✅ 已实现 | 是 | `tests/http_vendors/semantics_push_pull.rs#zentao_push_puts_bug_status_and_comment`、`#zentao_pull_reads_bugs_and_filters_since_cursor_client_side`、`tests/http_vendors/semantics_sync.rs#zentao_sync_reconciles_with_local_wins_policy`、`#pull_deduplicates_repeated_items_across_pages` |
| `syslog-forwarder` | ✅ 已实现 | ⛔ Unsupported：RFC 5424 转发是 fire-and-forget 单向日志投递，报文一旦发出不可更新/撤回 | ⛔ Unsupported：Syslog 是单向日志转发（无读取/查询接口） | ⛔ Unsupported：同上 | 否 | 未测（send 见 `tests/http_vendors/isolate_message.rs`） |
| `edr-isolation` | ✅ 已实现 | ✅ 已实现（`PATCH /v1/hosts/{host}/isolation`，受 dry-run 保护） | ✅ 已实现（`GET /v1/hosts?updated_since=..`、`GET /v1/events?since=..`） | ✅ 已实现（本地资产 ↔ EDR 主机对账） | 是 | `tests/http_vendors/semantics_edr_notify.rs#edr_push_patches_host_isolation_state_with_dry_run_marker`、`#edr_pull_reads_hosts_incrementally_and_normalizes_action`、`#edr_sync_reconciles_local_assets_with_edr_hosts` |
| `iam-scim` | ✅ 已实现（`PATCH /Users/{id}` 设置 `active=false`，仅持久化案件审批入口允许 Live） | ⛔ Unsupported：通用回写不能绕过案件目标校验 | ⛔ Unsupported：不复制身份目录 | ⛔ Unsupported：无读取对账 | 否 | `src/vendors/iam.rs` 编码单测与 `agf-api/tests/soar_iam.rs` 本地 HTTP/Mock/审批专项 |

## 横切保证

| 项 | 做法 |
|---|---|
| 鉴权与凭据 | 沿用既有 `AdapterSettings` / `SecretLookup`（`push`/`pull` 与 `send` 用同一份配置与凭据表） |
| 远端对象 id | `push` 的 `entity_id` **必须**来自 `send` 回执的 `remote_id`；缺失一律 `Validation` 拒绝 |
| 超时 / 重试 / 熔断 | 三条语义共用 `VendorAdapterImpl::invoke` → `agf_core::adapter::invoke_with_policy`（指数退避 + 半开探测） |
| 错误分类 | 5xx/超时/网络可重试；4xx 与业务错误码不可重试；`Unsupported` 不可重试（`Validation`） |
| 增量去重 | `pull` 按 `resource` 维护 `IncrementalWindow`（规范化 id 优先，无 id 用内容哈希） |
| 冲突策略 | 设置项 `sync_conflict_policy` = `external-wins`（默认，外部优先）/ `local-wins`（本地优先）；非法值在 `init` 阶段报 `Config`；每条裁决写入 `SyncOutcome.warnings` 并经 `tracing` 输出 |
