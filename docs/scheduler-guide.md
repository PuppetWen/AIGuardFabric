# 定时任务与云调度操作指南

入口为独立 `agf-scheduler` 服务，默认端口 9101；主控制台 API 端口 8080 不承接云执行器的 HTTP 回调。启用云后端前，按 [原生绑定与执行回执指南](scheduler-callback-execution-guide.md) 核对 API、调度器版本、原生任务采用证明与服务权限；已有部署不能仅凭本地源码推断已升级。

## 个人与离线使用

保留 `AGF_SCHEDULER_BACKEND=local-cron` 和 `AGF_SCHEDULER_TIMING=calendar`。六类任务使用五段 **UTC** 日历，辅助回归/CMS 任务使用间隔。

| 任务 | 本地默认 UTC 时间 | 任务名 |
|---|---|---|
| 资产统计 | 每日 02:00 | asset-inventory |
| 日志源拉取 | 每 10 分钟 | log-pull |
| 离线红队巡航 | 每周一 03:00 | redteam-cruise |
| 策略重载 | 每 5 分钟 | rule-hot-reload |
| 运行报表 | 每日 07:00 | report-generate |
| 文件归档 | 每月 1 日 04:00 | cold-archive |

`asset-inventory` 默认只汇总现有资产统计。需要每天自动盘点 AgentTeams 时，先在「阿里云 AgentTeams」启用连接并手动同步一次，再给调度器所在租户的服务 API Key 授予 `alicloud:write`、`assets:write`、`assets:read`，把 `AGF_SCHEDULER_AGENTTEAMS_SYNC_ENABLED=true` 写入部署环境并重启调度器。此时任务先读取当前连接版本、完成云盘点和资产发布，再读取统计；同步失败会记为失败，不会把旧统计冒充新盘点。Mock 连接可先按此步骤验证。Live 连接还须明确设置 `AGF_SCHEDULER_AGENTTEAMS_CONFIRM_LIVE=true`，否则调度器在发出同步请求前拒绝执行。Live 会调用真实云只读 API 并更新本地资产，先核对账号、实例、云权限和计划时区。查看 `/tasks` 中 `asset-inventory` 的最近结果，完成后到资产台账核对 Worker 和云快照时间。关闭 `AGF_SCHEDULER_AGENTTEAMS_SYNC_ENABLED` 即恢复仅统计；已有资产不会被自动删除。

例如北京时间每日 10:00 对应 UTC 02:00。修改 `.env` 中 `AGF_SCHEDULER_<任务名转大写并将连字符改下划线>_CRON` 后重启服务。空值使用默认日历，非法表达式会停止该任务并在 `/tasks` 显示原因。日历检查使用 Tokio，重启不会补跑错过的日历分钟。

需要短间隔开发验证时，设置 `AGF_SCHEDULER_TIMING=interval`、清空逐任务 `_CRON`，并设置 `AGF_SCHEDULER_INTERVAL_SECS=60`。数据库可用时，多个相同租户的调度实例共用领取记录；离线无数据库会明确显示 `receipts_persistent=false`。

### 日志实际入库

1. 控制台选择目标租户，进入「接入管理」，添加并启用 HTTP Pull 日志源。
2. 填写真实拉取地址、源所需的请求头、解析器和周期；源凭据按租户加密保存。
3. 创建当前租户的服务 API Key，权限包含 `sources:read`、`sources:write`，部署端写入 `AGF_SCHEDULER_API_KEY`。
4. `AGF_SCHEDULER_PULL_URLS` 留空。调度器读取完整源列表，只触发到期源；平台复用持久游标、并发领取和解析入库流程。
5. 在源详情检查最近拉取结果和事件数量，再到日志查询查看事件。单源失败不会伪装为全部成功。

旧 `PULL_URLS` 路径保留为兼容的本地解析统计，标记为降级，不能作为入库成功依据。平台 API Key 不会发送给日志上游；需要认证的上游应迁移到控制台源配置。

## 企业云 HTTP 调度

云 OpenAPI 身份用于创建和管理云任务；平台服务 API Key 用于访问本租户数据；回调令牌用于验证云执行器。三者不同，不能相互替换。

1. 在云控制台创建 HTTP 应用，取得应用 ID；确认执行器网络能访问调度服务。默认 Compose 只将 9101 映射到本机，企业应配置内网反向代理和 TLS，或显式修改 `AGF_SCHEDULER_BIND` 为已授权的内网监听地址。
2. 为该部署指定 `AGF_SCHEDULER_TENANT_ID`（非空 UUID），并配置同租户服务 API Key。原生绑定执行协议都需要 `alicloud:read`；资产统计另需 `assets:read`，启用 AgentTeams 自动盘点另需 `alicloud:write` 和 `assets:write`，策略重载需要 `policies:write`，日志拉取需要 `sources:read/write`，红队巡航需要 `redteam:read/execute`，报表与归档需要 `reports:write`。
3. 生成独立随机令牌，至少 32 字节，写入 `AGF_SCHEDULER_CALLBACK_TOKEN`；应用 ID 写入 `AGF_SCHEDULER_CALLBACK_APP_ID`。不要把令牌放 URL 或日志中。
4. 先启动主服务完成数据库迁移，在「阿里云 → 原生调度观察」完整观察当前应用/任务，明确采用并保存需要运行的启用 HTTP Job。云模式不接受 Mock 关联或无可信证明的旧记录。完成后设置 `AGF_SCHEDULER_BACKEND=schedulerx3` 并重启调度器；启动会检查平台身份与当前本地绑定，每次回调仍重新校验。
5. 在云控制台配置 HTTP 任务：POST `/api/v1/internal/jobs/{kind}`，Header `Authorization: Bearer <回调令牌>`；`kind` 为上表任务名，其中 report-generate 可简写 report，cold-archive 可简写 archive。
6. 日志拉取、红队、归档支持广播分片（最多 256 片），按源 ID、用例 key、文件名稳定分配；统计、重载和汇总报表建议单实例路由。云执行器会附带 `schedulerx-appId`、`schedulerx-jobId`、`schedulerx-jobExecutionId` 等请求头；平台验证应用和执行编号。超时建议超过任务实际耗时，服务端上限五分钟。
7. 成功条件为 HTTP 200 且 JSON `ok=true`。启停调用 OperateEnableJobs/OperateDisableJobs；立即执行调用 OperateExecuteJob。开始真实调用前，按项目第二阶段验收要求准备网络和云权限。

HTTP 应用和执行器配置以 [阿里云 HTTP 任务说明](https://help.aliyun.com/en/schedulerx/schedulerx-xxljob/user-guide/http-tasks) 为准。云 cron 使用云端支持的 Quartz 格式，不能直接照抄本地五段表达式；明确配置云任务时区。

## 查看结果与重试

### 红队巡航接入控制台

1. 启动主平台并配置 PostgreSQL；创建与 `AGF_SCHEDULER_TENANT_ID` 相同租户的服务 Key，将它通过部署环境变量 `AGF_SCHEDULER_API_KEY` 注入调度器，不写在命令参数或 URL 中。
2. `AGF_SERVER_URL` 指向主 API，例如本机 `http://127.0.0.1:8080`，Compose 使用 `http://agf-server:8080`。用例从主平台当前用例库选取，调度器的本地目录不再是本任务的执行依据。
3. 配置 `AGF_SCHEDULER_REDTEAM_CRUISE_CRON`（默认每周一 03:00 UTC）和 `AGF_SCHEDULER_REDTEAM_GUARD`（0–100，默认 30；Compose 同样传入）。该值是模拟参数，不是生产防护策略。
4. 在红队中心搜索 `scheduler-cruise`，检查完成状态、逐条证据、报告与模拟标记。调度器也将相同任务的 JSON/Markdown 保存到 `AGF_REPORT_DIR`；非默认租户使用其 UUID 子目录。缺少平台权限/网络或落盘失败都记为失败。
5. 巡航不启用 CI。成功只表示模拟任务和证据归档完成；不能据此放行生产。需要 CI 时使用 [红队 CI 脚本](redteam-guide.md)。模拟结果不再当作真实红队成功率上报 CMS；没有实际观测的指标省略。

同一执行编号和分片使用相同 Idempotency-Key；同一租户、同一调用身份重试返回原任务，包含原用例版本。参数改变返回 409，须核对原任务后使用新执行编号。服务 Key 轮换会改变调用身份；不要跨身份重试未核对的批次。平台任务到期/取消/失败不会被同一编号重跑；控制台复测会创建新任务。

分片使用 SHA-256 用例键稳定分配；每片最多 500 条，超出明确失败，不悄悄截断。空片显示跳过。每片读取证据上限 16 MiB；超限增加分片数。调度器最多轮询 240 秒后记失败，使用原执行编号重试可继续下载原任务；主平台任务仍受 10 分钟上限约束。JSON 与 Markdown 分别落盘，只有两个文件都成功且证据身份/数量正确才算任务成功；重试不覆盖内容不同的既有文件。

### 通用任务回执

- 访问调度服务 `/tasks`，检查实际后端、租户、持久回执和各任务最近结果。`/metrics` 与健康检查使用同一端口 9101。
- 云模式会停用对应的六个本地周期，避免同时执行；辅助规则回归与 CMS 上报仍本地运行。
- 云回调使用永久全局 AppId/JobId/JobExecutionId/分区事实，并分开确认准入与一次性启动。已完成的相同事实只返回原结果；运行中、未知或终态审计待出版时返回冲突并禁止重跑。读取原 factId 或 request UUID 核对状态，不要通过换请求 UUID、任务 kind 或绑定版本重试原业务。
- 云回调不使用旧 lane 的八次业务重试与依赖补跑。明确失败也不重跑原身份；进程中断、超时或启动响应丢失均可能为不确定。只有已知结果的同正文终态提交可显式恢复审计，无处理器调用。
- 本地 cron 仍沿用自己的 lane：明确失败最多八次，回执最长 30 天、每类最多 2048 条。该本地缓存不是云回调永久去重事实。外部系统效果仍需核对业务记录。

## 当前实现范围与后续验收

回调入口、本地日历、数据库领取和配置日志源已接上。分片已接通；同一执行批次禁止中途改变总分片数。本地会补跑未完成的上游，云回调等待上游最近批次全部分片成功；成功记录有效期 24 小时。云工作流自动发布仍待补齐。资产任务可显式启用 AgentTeams 定时盘点，其余云业务编排仍待完成；红队使用主平台持久模拟战役；运行报表为部署端 Markdown，文件归档为 gzip。控制台的 PDF/CSV 等业务报表与事件 Parquet 冷归档另有服务。创建云任务成功不能代替实际执行验收。

### English: scheduled campaign operation

Set `AGF_SERVER_URL`, `AGF_SCHEDULER_TENANT_ID` and a secret-injected `AGF_SCHEDULER_API_KEY` with `redteam:read/execute`. Cruises select the platform case library, save versioned inputs before execution and appear as `scheduler-cruise` tasks in the red-team console. Set the five-field UTC cron and simulator guard strength (0–100). Each shard supports 500 cases and 16 MiB of evidence; oversized shards fail rather than truncate. Empty shards explicitly skip.

Retries under the same caller and execution ID reuse the saved task; altered parameters conflict. Credential rotation changes the caller, so reconcile unfinished runs before retrying with another key. Interrupted or failed campaigns require a new run. The scheduler downloads immutable JSON and Markdown, validates identity and completion, and refuses to overwrite different artifacts. Both files must be saved before success is recorded. Cruises do not enable CI and do not supply live security metrics. See the separate CI guide for explicit gate checks.

## Kubernetes 接入

调度器 Pod 的健康、指标和回调统一监听 `ports.schedulerHealth`（默认 9101）。Service 的兼容 metrics 端口 9100 转发到相同监听，Pod 注解抓取 9101。探针使用已声明的 `sched-health` 端口。

通过 `scheduler.env` 配置租户 UUID、云应用 ID 和 backend；服务 Key 与回调令牌使用 `scheduler.extraEnv` 的 `secretKeyRef` 引用已有 Secret。不要写进普通 ConfigMap。云执行器可走内网服务或已有 TLS 反向代理。

启用 NetworkPolicy 时，在企业 values 覆盖文件中配置 `networkPolicy.schedulerCallbackCidrs`（执行器实际来源 CIDR 列表），或 `networkPolicy.schedulerCallbackPeers`（标准 namespaceSelector/podSelector 列表）。默认两者为空，不开放云回调来源。来源配置只影响调度端口；令牌和租户校验仍然必须通过。
