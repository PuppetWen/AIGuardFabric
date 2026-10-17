# AgentTeams collector 任务错误人工处理

本增量提供 collector 报错收件箱、人工标注、原请求回执和显式归档。它不执行任务重放，不向 SDK 重送遥测，不调用云厂商操作。`collector_reported_error` 仅表示可信 collector 事件中 `kind=task,status=error`，不等于云端已确认任务失败。

2026-10-02：人工处理增量已通过后端回归 772 项、专属 PostgreSQL 验收 7 项、前端全量测试 635 项以及格式、严格 Clippy 和 500 行门禁。源码已接入，尚未部署到当前站点；完整角色映射和任务编排定义同步仍在实现。这些人工标注不会重跑业务任务。

## 在控制台操作

部署此增量后，从左侧“阿里云”进入“错误与人工处理”，或打开 `/alicloud?tab=task-handling`。首次进入不会自动读取或提交操作。

1. 确认右上角当前租户，选择时间范围（默认最近 24 小时，最多 30 天），点击“刷新错误证据”。
2. 选择一条记录，核对来源、原任务编号、调用链、时间、错误摘要与已有处理历史。需要排查链路时使用页面内的调用链入口。
3. 选择“已查看”“报告外部处理”或“操作人标记已处理”，确认后点击保存。最后两项只是人工声明，页面不会显示为已验证的云执行结果。
4. 保存后出现回执和请求编号。如果网络中断或结果未知，点击读取原回执；找不到回执时保留原编号，不重复创建新操作。版本冲突时先核对当前详情，明确选择重新准备独立操作。
5. 已标注记录可显式归档，释放活动处理容量。原错误事实、最后标注和请求回执仍可查询。归档不会删除云任务或重派任务。

只有读取权限时仍可查看证据和回执。写入同时需要“阿里云写入”和“日志来源写入”；页面会说明缺失权限。来源停用后可做本地标注，来源删除后只能读取已有事实或归档已有标注。列表提示截断时请缩小时间范围，避免遗漏较早证据。

## Console steps in English

After deployment, open **AliCloud → Errors and operator handling**, or `/alicloud?tab=task-handling`.

1. Check the selected tenant, choose a time range of up to 30 days, and manually refresh the error evidence.
2. Select an event and review its original source, task, trace, timestamp, error preview and handling history.
3. Choose **Acknowledged**, **External action reported** or **Resolved by operator**, then explicitly save. Operator declarations do not confirm a cloud or business execution.
4. Keep the request ID. When a reply is lost, read the original receipt before taking another action. A missing receipt does not authorize a duplicate submission. For a version conflict, inspect the current event and explicitly prepare a new action.
5. Explicitly archive an already handled event when appropriate. Original evidence and receipts remain readable; archiving does not delete or rerun a cloud task.

Read-only users can inspect evidence and receipts. Editing requires both `alicloud:write` and `sources:write`. Narrow the time range when the evidence list reports truncation.

## 查看和选择

读取需要 `alicloud:read` 和 `sources:read`。列表默认最近24小时，可按原 `source_id`、`scope_id` 和时间窗筛选；窗口最多30天，结束时间最多允许当前时间之后60秒。原始 audit UUID、binding、scope、task/trace 和 Mock 属性来自已存 collector 记录，不用当前云库存推测或覆盖历史身份。

每页1至100条；总数与最新最多2000条证据来自同一 SQL 语句或内存锁。`total` 与页大小无关，`truncated=true` 表示有证据未展示，`complete=false` 始终成立。游标认证租户、查询、接收水位和完整有界快照，30分钟过期。篡改/改条件返回400，快照改变返回409；请显式刷新，不拼接新旧页。人工处理状态独立读取，可能随并发标注变化，不声称它与原证据分页构成一个强一致云快照。

所有 GET 都仅读取，不初始化配置、领取任务、写审计或调用 provider。列表和详情只返回原记录已有的脱敏截断 messagePreview，以及原 fromTeam/fromWorker；不返回原始日志、原始 message、请求头、凭据或内部配置摘要。源证明是 tenant 域 AEAD 认证的 opaque 字符串，不能解析或自行构造，也不能将其解释为云授权证明。

## 人工标注

写入需要当前 `alicloud:write` 和 `sources:write`。可选择三种操作人标注：

- `acknowledged`：操作人已查看。
- `external_action_reported`：操作人报告已在外部处理；平台未验证该外部行为。
- `resolved_by_operator`：操作人将其标注为已处理；不表示云或业务执行成功。

首次标注使用 `expected_version=0`，后续使用详情的当前处理版本。必须同时回传详情的实际 `cloudConfigurationVersion` 和 `fingerprint`，不能为没有修订号的源配置编造版本。服务器在源锁后重读来源和原证据，并在审计等待后复查原认证、JWT 有效期和当前权限。整个请求使用原110秒预算，不续期。

来源存在但被停用时可以进行纯本地人工标注；不会因此重新启用它。已删除来源仍可查看原事实和处理历史及显式归档，不能新增标注。当前 source 信息仅是操作资格，不能替代原 binding/scope 身份。独立用户/角色/Key store 只做提交前新鲜检查，不宣称跨所有独立 store 完全线性化。

每个提交都显式生成新的 UUID。同原 UUID、同正文、同操作者和用途返回原已提交回执，不重复写配置或审计；异正文/用途返回409。未知回复先 `GET /requests/{原UUID}`，不要自动换 UUID 重发或把查到的原回执称为新执行。

409 时保留原草稿、来源证明和原 UUID，读取原请求回执和当前详情；只有用户明确采纳当前版本并发起独立新标注后才生成新 UUID。不同 decision 不得显示云执行成功绿态，所有回执 `cloudExecutionConfirmed=false,businessReplay=false`。

## 归档与容量

最多128条活动人工处理，每条最多20次修订。容量达到限制后可显式归档已经标注的记录；没有人工标注的原错误事件不能凭空归档任务。

每批1至99个唯一 event UUID，最多31个唯一 source。回传列表当前 `generation`、各现存来源的 opaque fingerprint 及真实 cloud version；已删除来源使用 null fingerprint，全部已删除时 cloud version 为 null。归档事务重验原始证据、当前权限和来源存在/删除事实。

归档释放修订正文，将处理记录变为永久 tombstone；原 collector 事件、原状态、最后人工标注和每次请求 UUID 回执不删除。归档不是云任务归档，不释放或重派业务执行资格。归档后仍可按原 UUID 仅读取原回执。

同归档 UUID 重读是真正的纯 replay。不同新 UUID 即使所有条目已归档，也需要完整 generation/来源/权限校验，并写新的本地永久 request receipt 和 Create 审计；`changedCount=0` 时 generation 不变，不能把这次新配置写入称为无写操作。

## API

| 方法 | 路径（前缀 `/api/v1/alicloud/agentteams/task-handling`） | 行为 |
|---|---|---|
| GET | `/` | 错误证据列表与当前本地处理容量 |
| GET | `/events/{id}` | 原 audit UUID 详情、当前来源资格与人工修订 |
| PUT | `/events/{id}/resolution` | 显式 CAS 人工标注 |
| POST | `/archive` | 显式 CAS 归档人工处理历史 |
| GET | `/requests/{id}` | 永久原请求 UUID 回执，不重新提交 |

路径列表实际根路径无结尾 `/`。响应是直接 JSON DTO。输入严格 snake_case，输出安全 camelCase，不接受 client tenant、actor、status、notes、raw 输入或 Retry/Replay 指令；JSON 请求最多64KiB，错误使用固定安全 problem 响应，不回显正文。

SQL 模式将原 collector 行（FOR SHARE）、tenant、cloud/source 配置、加密处理记录、永久 UUID 回执和成功审计置于同一事务，审计失败完整回滚。来源锁与既有 source configuration writer 使用同一 `tenant:log-source:id` advisory key；锁顺序为资产治理→tenant→cloud→sorted sources→sorted 原事件→journal→sorted related→audit。

离线模式在同 ConfigStore mutex 中检查来源/权限配置、序列化全部候选并同步封存审计，成功后仅发布内存 map；原 collector Sink 独立 mutex，正式写接口保持原事件 immutable。离线数据仅进程内，不声称重启持久化或跨多个 API 实例数据库一致性。该模式不能替代 SQL 验收。
