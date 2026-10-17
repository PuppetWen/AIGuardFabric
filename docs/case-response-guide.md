# 案件处置与 SOAR 操作指南

平台内处置作用于 AIGuardFabric 管理的 API Key、模型网关、MCP 代理和通知渠道。另可配置 EDR 隔离案件关联主机，或经 SCIM 2.0 停用案件关联身份；“隔离 Agent 出口”仍只限制平台流量，不代表电脑断网。

## 接入身份

1. 在资产台账登记或通过采集器发现 Agent。
2. 系统设置 → API Key → 创建，为该 Agent 选择“绑定 Agent”，授予实际需要的 `models:read`、`models:write`、`policies:read` 等权限。密钥明文仅展示一次。
3. 将此密钥配置到模型客户端和 MCP 代理。服务端从已验证密钥读取 Agent 身份；请求不能冒用另一个 Agent。每个 Agent 使用独立密钥。
4. 模型 API 使用 `/v1/chat/completions`，Messages 客户端使用 `/v1/messages`；均通过平台网关地址接入。MCP 使用项目 CLI 的代理模式。直接访问第三方平台的流量不经过本平台处置。
5. 同一 Agent 换会话仍受 Agent 配额和隔离控制约束。未绑定 Agent 的旧密钥应替换为绑定密钥，再进行隔离验收。

## 新建与流转案件

在“案件中心”点击“新建案件”，填写标题、等级、说明并选择关联资产。资产选择支持服务端搜索；仅能关联当前租户存在的资产。

从红队结果进入“风险发现”详情，先核对证据、状态与关联资产，再点击“核对证据后关联新案件”。案件表单会从当前租户重新读取该发现，预填标题、摘要、等级和有权读取的资产，并显示待关联的发现编号；只有点击确认才会创建案件。成功后直接打开新案件，详情中的发现编号可以返回原始证据。此操作需要 `findings:read` 和 `cases:write`；若无建案权限或发现已不存在，页面会说明原因，不会自动提交。演示发现也只能由操作员确认后建案。

创建成功后，可以在“审计日志”按案件详情中的 UUID 搜索这次建案记录。PostgreSQL 部署会把案件、创建时间线、告警关联和成功审计一起提交；如果审计无法写入，创建请求会失败且不会留下半成品案件。此时先排查数据库或审计故障，再重新提交，勿凭页面错误推断案件已经创建。

后续修改案件状态也可以按同一 UUID 在审计日志核对。PostgreSQL 部署会把状态、时间线和成功审计一起提交；审计故障时状态保持原值。对已经达到的相同状态重复提交不会再追加时间线或成功审计。

点击案件卡片打开详情。“流转案件状态”仅展示当前允许的下一状态：新建 → 调查中 → 处置中/已解决 → 已解决 → 关闭。已解决案件可以重新调查；每次流转填写说明。列表支持分页和跨页搜索。

详情地址为 `/cases/<案件 UUID>`，可复制地址、刷新或重新打开。使用 PostgreSQL 时，接口成功前已保存同一个案件 ID、状态和时间线；并发创建不会重用编号，一个告警只能属于一个案件。

## 执行一次处置

告警自动建案和处置模板入口在案件中心上方，见 [自动响应指南](automatic-response-guide.md)。默认“只建待研判案件”模板不会执行处置；先预览、再启用，新告警匹配后创建案件。真实 Agent/MCP 红队命中的告警可走此入口；模拟和无结论不生成告警。选择处置模板时仍须在案件内审批并核对实际步骤结果。

1. 打开案件，点击“执行处置 / YAML 剧本”。
2. 选择动作和目标，填写原因。资产必须已关联当前案件，类型须匹配。
3. 默认“演练”开启，仅验证剧本结构、条件及步骤编排，不验证真实目标或调用外部系统。演练完成不代表实际处置成功。
4. 核对目标后关闭演练，点击“提交执行任务”。保存成功只表示已进入流程。关闭弹窗，在“审批与执行记录”中打开任务、核对保存的目标并批准。审批需要登录用户具有 `cases:admin`，执行时重新检查其动作权限；API Key 不可冒充人工审批。个人使用可自行审批；企业可选择“要求另一位管理员审批”。
5. 查看状态与逐步结果。`completed` 且无失败步骤才代表本次动作完成；`approval` 为待审批、`waiting` 为等待、`review` 为结果待核对。超时可能已有部分步骤完成，应核对处置记录，不能认为全部回滚。
6. 可逆控制显示在案件详情，点击“解除”后下一次请求读取新状态。API Key 吊销不可解除，须新建密钥并更新客户端配置。

| 动作 | 目标与效果 | 动作权限 |
|---|---|---|
| 隔离 Agent 出口 | 拒绝绑定 Agent 的后续模型/MCP 请求及 MCP 返回检查 | `policies:write` |
| 通过 EDR 隔离主机 | 向已配置的 EDR 发送指定主机隔离指令；Mock 不联网，EDR 默认 dry-run；以回执和远端任务核对实际隔离 | `integrations:write`、`policies:write`，且由 `cases:admin` 人工审批 |
| 通过 SCIM 停用外部身份 | 对已绑定的 SCIM 用户发送 `active=false` PATCH；Mock 不联网，Live 审批后才调用；以回执和身份平台状态核对 | `integrations:write`、`policies:write`，且由 `cases:admin` 人工审批 |
| 吊销平台 API Key | 选择当前租户密钥；吊销后下一次认证被拒绝 | `settings:admin` |
| 封禁域名/IP | 拦截代理请求/返回中出现的目标域名、子域名、URL 或 IP；不修改主机防火墙 | `policies:write` |
| 终止代理会话 | 根据客户端传递的代理会话 ID 拒绝后续请求及 MCP 返回检查 | `policies:write` |
| 强制本地模型 | 选择 Agent 和已启用的本地端点；覆盖请求模型、禁用回退，端点不可用时拒绝 | `policies:write` |
| 禁用 MCP HTTP 端点 | 选择已登记 HTTP 代理端点对应的 MCP 资产；拒绝该端点的发现、工具请求和返回检查，其他服务的同名工具不受影响。关闭传统会话的 DELETE 仍可执行 | `policies:write` |
| 禁用其他 MCP/撤销 Skill 工具访问 | 目标资产必须登记 `tools`；没有可信端点绑定时按工具名在当前租户代理拦截，同名工具也受影响 | `policies:write` |
| 发送处置通知 | 使用系统设置中已启用渠道；站内消息可离线验证，外部渠道按实际回执判定 | `notifications:write` |

运行中的模型流不会强制回溯撤销已返回内容；新请求会被拦截。代理会话处置不等于退出控制台登录。通知渠道未配置、目标不存在、权限不足或模拟环境禁止外部通知时，显示失败，不伪造成功。

### EDR 主机隔离接入

1. 在“集成中心”找到 `edr-isolation`。先启用 Mock，保存配置并进行本地业务调用，确认回执标记为 `mocked`；Mock 不向外部平台发请求。
   关闭 Mock 后，集成中心只允许读取 EDR 主机清单；真实发送、回写和同步等写操作不能在集成页直接执行，必须从关联资产的持久化案件任务审批后发起。
2. 从 EDR 控制台复制真实主机编号。新资产可在“资产台账 → 登记资产”填写编号；自动发现或此前登记的资产，在台账详情的“资产治理与变更记录 → 绑定或修改 EDR 主机”保存。此操作需要 `assets:write`、变更原因和详情中的当前版本；多人同时修改时旧版本返回 409。留空保存可解除绑定。
3. 把资产关联到案件。在案件详情选择“通过 EDR 隔离主机”，选择该资产并填写原因；页面自动读取绑定编号与当前集成版本，不要求再次手输主机。未绑定、编号不匹配、资产已归档或已拒绝时服务端拒绝执行。变更配置或资产绑定后须刷新再提交。演练只检查剧本编排，不发送隔离请求。
4. 真实接入时，在集成配置填写 EDR `endpoint` 和 `api_token`，关闭 Mock。EDR 的 `dry_run` 默认 `true`：此时会发送带 dry-run 标记的请求，但是否真正不落地取决于远端实现；先用测试主机验证。确认远端支持后，只有显式设置 `dry_run=false` 才发送真实隔离指令。
5. 关闭案件弹窗的演练开关，提交任务，再由具有 `cases:admin` 的用户核对保存的资产、主机编号、配置版本和原因并审批。企业可开启双人审批。未经审批不会调用 EDR；旧配置版本、租户/资产不匹配、非法主机编号均拒绝。
6. 查看案件执行记录和“集成中心 → 调用记录”中的请求编号与回执。调用超时或结果不确定会停在 `review`，不会自动重放；先查 EDR 远端任务，再选择“核实已完成”或停止。相同任务步骤重试仍使用相同请求编号，不能用重试绕过幂等回执。此动作不会出现在平台代理控制列表中，也不能通过该列表解除；解除应在 EDR 平台执行并复核。

YAML 步骤写法：`action: isolate-host`，`params` 包含 `asset_id`（案件关联资产 UUID）、`host_id`（EDR 主机编号）、`configuration_version`（当前集成版本）和 `reason`。此动作只能通过持久化 `/playbook-runs` 审批流程真实执行；旧同步 `/playbook` 仅可用于演练。

### SCIM 外部身份停用接入

1. 确认身份平台提供 SCIM 2.0 `PATCH /Users/{id}`，令牌具有修改用户的最小权限。`iam-scim` 的 `endpoint` 填 SCIM 基地址（例如 `https://idp.example/scim/v2`），`api_token` 填 Bearer 令牌。非本机地址必须使用 HTTPS；厂商若没有标准 PATCH 接口，需先部署兼容网关。先启用 Mock 并验证回执；Mock 不调用身份平台。
2. 在“资产台账”登记 `credential` 类型的身份资产。从身份平台复制**资源 ID**（不是邮箱或显示名），登记时填 `scim_user_id`，或在已有资产详情“资产治理与变更记录 → 绑定或修改 SCIM 用户”设置。绑定需要 `assets:write`、变更原因和资产当前版本；旧版本返回 409。留空可解除绑定。
3. 把该资产关联到案件。在“执行处置 / YAML 剧本”选择“通过 SCIM 停用外部身份”、资产与原因；页面读取绑定用户和当前配置版本。未绑定、编号不匹配、非凭据资产或已归档/拒绝资产，服务端拒绝。演练只检查编排，不触网，也不验证外部凭据。
4. 关闭 Mock、填完整 HTTPS 配置后，使用**专门测试账号**验证。SCIM 没有通用 dry-run 开关；启用真实配置并审批即会发送 `PATCH /Users/{id}`，将 `active` 设置为 `false`。集成中心不能直接发送 Live 停用；只展示回执，真实执行必须由持久化案件任务经人工审批。企业可要求另一位管理员复核。
5. 在案件执行记录和集成调用记录查请求编号及加密回执，并在身份平台核对目标用户 `active=false`。上游超时、回执不确定或审计写入失败时，任务进入人工核对，不会自动重试。重新启用身份不由此动作执行，应在身份平台按其审批流程操作。

YAML 步骤可写 `action: deactivate-external-user`，`params` 包含 `asset_id`、`user_id`（绑定的 SCIM 资源 ID）、`configuration_version` 和 `reason`。真实执行只接受持久化 `/playbook-runs` 审批流程。SCIM PATCH 的形态遵循 [RFC 7644 §3.5.2](https://www.rfc-editor.org/rfc/rfc7644#section-3.5.2)；不同产品支持的操作需在测试租户核实。

## YAML 剧本

在操作窗口勾选“使用 YAML 剧本”，可以组合条件、动作、通知、持久化等待和逐步审批。以下 UUID 应替换为案件关联 Agent 和实际待吊销 API Key：

```yaml
key: contain-confirmed-incident
name: 已确认事件遏制
trigger:
  min_severity: high
require_approval: true
timeout_secs: 120
steps:
  - name: 隔离 Agent
    action: isolate-agent
    params:
      asset_id: REPLACE_AGENT_UUID
      reason: 已确认异常调用
    timeout_secs: 10
  - name: 吊销泄露密钥
    action: revoke-credential
    params:
      api_key_id: REPLACE_API_KEY_UUID
    timeout_secs: 10
  - name: 通知负责人
    notify_channel: in-app
    timeout_secs: 10
```

每步 `params` 会单独传给执行器，前一步的参数不会污染后一步。`continue_on_error: true` 允许记录错误后继续，调用方仍必须检查 `has_failure`。

异步流程最多 100 步、总执行时限 1–604800 秒（7 天）。初始审批最多等 24 小时，批准后开始总计时；后续审批与等待计入总时限。普通动作单步最多执行 60 秒，长期延迟使用 `params.wait_secs`，不会持续占用 HTTP 请求。旧 `/playbook` 接口保留同步兼容和演练，同步等待仅支持 0–30 秒。

自定义 YAML 不声明审批的可自动动作可由有权限的账号或 API Key 提交。`require_approval: true` 或吊销密钥/Skill 会要求初始审批；独立的 `params.require_approval` 步骤到达时会要求新的审批。提交与每次人工决定均保存操作者、目标快照、时间和版本；终态写入案件时间线。执行身份被停用、密钥被吊销或权限收回后，不会沿用旧权限继续动作。

## 等待、审批与中断恢复

```yaml
key: staged-response
name: 分阶段处置
trigger: {}
require_approval: true
timeout_secs: 7200
steps:
  - name: 等待观察窗口
    params:
      wait_secs: 3600
  - name: 人工核对后继续
    params:
      require_approval: true
  - name: 封禁已确认域名
    action: block-domain
    params:
      domain: replace-with-confirmed-domain.example
      reason: 已核对观察窗口证据
```

1. 提交后在案件的“审批与执行记录”打开任务。查看原始步骤/目标、当前步骤和版本；审批时填写理由。多人同时处理只接受第一个有效版本，冲突会保留填写内容，须刷新并重新核对。
2. `waiting` 和 `approval` 可跨服务重启恢复；刷新网页可继续处理同一任务。待执行或等待中的任务可取消，已执行动作不会撤销。
3. 如果服务在动作进行中崩溃，租约到期后标为 `review`，不会自动重放。先检查案件处置列表、通知回执和目标系统，再由管理员选择“核实已完成”“明确重试当前步骤”或“停止后续步骤”。确认完成必须有实际证据；重试可能造成重复通知或动作。
4. 等待超时、审批拒绝、账号停用、权限不足及步骤失败会保留原因和已完成结果。`continue_on_error: true` 可继续普通失败步骤，但不会自动越过结果不确定的动作。

API：`POST /api/v1/cases/{case}/playbook-runs` 接受 `yaml` 或 `playbook`，可加 `separate_approver: true`，返回 HTTP 202 和 `run.id`。相同路径 GET 为分页列表；`/{run}` GET 查看详情。`/{run}/decision` POST 发送 `expected_version`、`action`、`reason`，动作包括 `approve`、`reject`、`cancel`；结果待核对时可用 `confirm-completed`、`retry`、`abort`。不要把 202 当成动作已完成。

English: Open a case, dry-run the playbook, then submit a durable run. Review its saved targets under **Approvals and runs** and approve separately. Two-person review requires a different administrator. PostgreSQL preserves waits and decisions across restarts. Each action rechecks current permissions. A run interrupted during a side effect enters **Outcome needs review** rather than replaying automatically. Inspect actual effects before confirming completion, explicitly retrying, or stopping remaining steps. The maximum execution window is seven days; initial approval expires after 24 hours. Closing the browser does not cancel a run.

## 本地验收

先使用独立测试 Agent、测试密钥、测试案件和站内通知。验证演练不影响调用，再隔离并确认请求被拒绝，解除后确认恢复；最后使用可废弃测试密钥验证吊销。不要用生产密钥做吊销演练。

使用 PostgreSQL 时，处置与剧本记录同步保存，其他实例下一次请求读取相同控制；内存运行模式不能提供重启后的持久性。
