# AgentTeams 编排来源与接入边界

## 已实现的能力与本候选

现有「阿里云 → 资源盘点」读取 Team、Worker、人类人员和任务观测；任务观测、消息审计及 Trace 不能反推任务依赖。当前已保存的 AgentTeams `2026-06-05` 合同没有可用于本功能的编排定义读写 API。云端 DAG 显示“未提供”，不能显示成已获取的空图。

本候选修正库的完整定义比较和平台优先合并结果，并提供 `agentteams::orchestration` 的显式 Mock 声明同步。它只验证应用提供的定义与独立 Mock 接收器之间的状态，尚未注册控制台 API 或页面。库桥的 `durable=false`，原编号事实仅保留在当前对象/进程，不能承诺重启或双实例一致性。下一持久入口须采用同租户 CAS、永久编号与成功审计的同一事务。

本候选不会创建、执行或重放业务任务；不会为节点的 Worker 授予权限；不会写入真实云端。声明成功时 `consumer_applied=null`。Role 仍须在真实角色治理入口中明确采用，Key 原权限与角色约束取交集。

## 应用提供的声明

1. 先完整盘点真实 Team/Worker，保留准确的租户、Team ID 和 Worker ID。不要把人类人员名字写入 Worker 列表。
2. 由应用维护者列出节点 ID、名称、执行 Worker、上游节点、`manual` / `event` / `cron`。节点最多 128，定义 JSON 最多 256 KiB。名称和 ID 不包含提示词、个人信息、脚本或密钥。
3. 使用 `DefinitionDocument::from_application(team, nodes)` 构造声明；`inventory_fingerprint` 来自明确采用的库存。导入只允许声明字段，未知字段、重复 ID、未知 Worker、未知依赖或循环均拒绝。
4. `MockDefinitionBridge::preview(intent)` 只比较新增、删除和实际字段变化，不改状态。明确读取当前版本并选择 `pull`、`push` 或 `both`；`both` 以操作者提供的应用声明为准。
5. 明确 `confirm_mock=true` 后调用一次 `apply`。网络/调用结果不明确时读取原编号回执；相同编号不同正文会冲突。此库没有任何云传输路径。
6. `receipt(original_id)` 返回原始版本事实。之后的读取、其他同步或旧编号重读，不把原回执变成“当前应用已执行”。最多保留 128 个编号；容量已满会拒绝新动作，不删除旧编号以允许重派。

## 三种实际接入方式

| 场景 | 操作位置与身份 | 能验证什么 |
|---|---|---|
| 侧车/终端采集与 MCP 代理 | 「Agent 管理 → 接入向导」选择目标系统；按 [Agent 接入指南](agent-onboarding-guide.md) 配置平台地址、实际租户 UUID 和独立采集 Key。项目根用 `AGF_AGENT_PROJECT_ROOTS` 明确指定，再按向导配置真实 MCP 工具代理。 | 终端发现/采集与经代理的 MCP 请求；仅发现配置不证明已转发全部流量。不能自动接管任意已运行程序。 |
| SDK 任务与消息审计 | 先完整盘点，在「日志源」建 APIWebhook 源，再在「消息与调用审计」明确绑定。按 [Python SDK](../sdk/agentteams/python/README.md) 或 [Node SDK](../sdk/agentteams/node/README.md) 配置独立 `sources:write` Key、准确 source/binding/scope 和独立队列目录，显式包装实际业务函数。 | 真实函数的 task/call/message/heartbeat；SDK 保留原值和异常，不再执行业务。`sources:write` 是租户级权限，不是单一源权限。需要接入代码，不能宣称自动 SDK 注入或任意应用零改造。 |
| 支持端点配置的模型客户端 | 使用独立 `models:read` / `models:write` 模型 Key，在「模型网关」核对真实模型 ID。按客户端实际支持项配置平台 `/v1` Base URL、Key 和模型；不支持的客户端需显式传入配置。 | 经平台模型网关的请求、当前平台策略和用量。无需改业务函数只适用于支持配置的客户端；不证明应用内部所有 Worker/DAG/消息已被采集。 |

采集 Key、模型 Key 和控制台账号分别使用，不把管理员密码放入终端/SDK。企业环境使用 HTTPS、每应用独立配置和队列；个人单机可以在专用本地 Mock 环境验证，再按向导核对范围。重启/迁移后的事实持久性以真实 `durable` 字段为准。回滚时恢复原应用端点或 MCP 配置，停止本次代理并撤销本次 Key，保留队列与审计资料。

## English

The existing inventory reads Teams, Workers, human members and task observations. It does not infer a DAG from timestamps, assignments or traces. The saved `2026-06-05` vendor contract does not provide a supported orchestration-definition write path for this feature. A missing DAG remains “not provided”.

This candidate corrects complete definition comparison and platform-priority merge output. Its bounded `agentteams::orchestration` library bridge explicitly synchronizes an application-owned declaration with an isolated Mock receiver. No control-panel API or page is registered yet. `durable=false` means request facts survive only in this object/process; durable multi-instance publication requires the later CAS/intent/audit transaction. `consumer_applied=null` never means an application executed the declaration.

Declare at most 128 nodes and 256 KiB of JSON using actual tenant/Team/Worker identities. Preview first, review the version and direction, explicitly confirm Mock, and apply once with a unique request ID. Identical ID/body replays read the original fact; a changed body conflicts. Unknown fields, unknown Workers, duplicate IDs and cycles are rejected. There is no script, business execution or vendor dispatch path.

Use the existing **Agent Management onboarding wizard** for terminal discovery/MCP proxy configuration, the **message audit binding plus explicit Python/Node SDK** for task/call/message telemetry, or the **Model Gateway** with an independently issued model Key for clients that support an endpoint configuration. The SDK requires explicit integration; terminal discovery alone does not prove traffic forwarding. Model endpoint configuration does not reconstruct an application's DAG. Collector `sources:write` is tenant-wide, not source-specific. Keep passwords, model Keys and collector Keys separate; never paste secrets into a declaration.

Follow the linked onboarding and SDK guides for supported operating systems, project roots, exact scopes and rollback. Enterprise deployments use HTTPS and separate application queues. Local Mock tests do not certify a real vendor, a real Claude Code installation, application execution, automatic injection or Phase 2 deployment.
