# AgentTeams 应用编排定义操作指南 / Application orchestration guide

本功能保存应用所有的声明，并在阶段一的独立 Mock 接收端之间显式同步。它不执行节点、不注册定时器、不写厂商 DAG，也不证明消费者已生效。真实 AgentTeams 的 Team/Worker/人员关系、云端任务观察、消息审计和平台 Role 约束是不同功能；不要以此替代它们。

This feature stores application-owned declarations and explicitly synchronizes a separate stage-one Mock receiver. It does not execute nodes, register timers, write vendor DAGs or prove consumer application. Team/Worker membership, cloud task observations, message auditing and platform Role constraints are separate features.

## 入口、账号与准备 / Entry, identity and preparation

候选独立组件：`OrchestrationPanel`。正式接入位置为阿里云连接页的编排定义标签 `/alicloud?tab=agentteams-orchestration`，需由发布方注册该标签后使用。候选冻结不代表该入口已经部署。

The candidate exports `OrchestrationPanel` for the AliCloud orchestration tab `/alicloud?tab=agentteams-orchestration`. The release owner must register this tab. A frozen candidate does not mean the entry has been deployed.

读取需要 `alicloud:read`。预览和提交需要当前管理员**用户会话**，权限为 `platform:admin`、`alicloud:read`、`alicloud:write`。API Key 和 CloudRole 字符串不能提供提交权限。系统在提交和审计等待之后重新核对原会话、原 JWT、当前角色及租户资格。

Reading requires `alicloud:read`. Preview and commit require a current administrator **user session** with `platform:admin`, `alicloud:read` and `alicloud:write`. API Keys and CloudRole strings cannot grant publication authority. The system rechecks the original session/JWT, current Roles and tenant qualification during publication, including after the audit wait.

1. 打开 `/alicloud` 的连接设置，明确选择 **AgentTeams Mock**，填写地区和实例标识并保存。不要将现有 Live 连接悄悄改为 Mock。
2. 在 AgentTeams 页人工点击完整盘点；盘点结果必须是当前配置版本、关系完整且每个 Worker 对应同租户的有效 Agent 资产。
3. 打开编排定义页，人工选择已盘点 Team。初次 GET 不读云、不保存定义、不初始化接收端。没有可用库存时不会显示示例 Team。

1. Open connection settings at `/alicloud`, explicitly choose **AgentTeams Mock**, enter the region and instance, and save. Do not silently convert a Live connection to Mock.
2. Manually run complete AgentTeams inventory. It must match the current configuration revision, contain complete relationships and map each Worker to a live Agent asset in the same tenant.
3. Open the orchestration tab and choose an observed Team manually. Initial GET does not read the cloud, save a definition or initialize a receiver. Unavailable inventory produces no sample Team.

Live 保存/同步不支持：现有可信厂商接口没有可用的 DAG 定义写合同。`ListTeamTasks` 是云任务观察，不能当作应用 DAG；创建实例的异步任务也不是业务重放。

Live save/sync is unsupported: there is no trusted vendor DAG-definition write contract. `ListTeamTasks` provides task observations, not application DAGs; instance-creation asynchronous tasks are not business replay.

## 编辑或导入 / Edit or import

可以使用节点表单，也可粘贴 JSON。节点表单不默认指派 Worker：填唯一节点 ID/名称、选择实际 Worker、选择已有依赖节点，再点击“仅加入草稿节点”。被其他节点引用的节点不能直接移除；先在 JSON 中明确修改依赖。

Use the node form or paste JSON. The form never assigns a Worker by default: enter a unique node ID/name, select actual Workers and existing dependencies, then choose “Add a node to the draft only.” Nodes referenced by others cannot be removed directly; change dependencies explicitly in JSON first.

使用服务端提供的当前模板，不手工伪造租户、Team 或库存摘要。声明包含 `schema_version=1`、`tenant_id`、`cloud_team_id`、`inventory_fingerprint`、`nodes`。每个节点只接受：

Use the current server template rather than inventing tenant, Team or inventory digests. The declaration contains `schema_version=1`, `tenant_id`, `cloud_team_id`, `inventory_fingerprint`, and `nodes`. Each node accepts only:

| 字段 / Field | 操作 / Meaning |
|---|---|
| `node_id` | 唯一且非空，最多128 UTF-8字节 / Unique, nonempty, up to 128 UTF-8 bytes |
| `name` | 非空，最多256 UTF-8字节 / Nonempty, up to 256 UTF-8 bytes |
| `agent_ids` | 人工选择盘点中的 Worker 名称，1–32项 / Explicit observed Worker names, 1–32 entries |
| `depends_on` | 已有节点 ID，不允许自身引用或环 / Existing node IDs, no self reference or cycles |
| `trigger` | `manual`、`event` 或 `cron`，仅声明 / `manual`, `event` or `cron`, declaration only |
| `cron` | 仅 cron 节点允许非空文本；其他节点省略或 null / Nonempty only for cron nodes, omitted/null otherwise |

最多128节点、声明256KiB；未知字段、重复引用、未知 Worker、环、跨租户/过期库存都拒绝。不要将密码、API Key、消息正文、脚本或业务输入写入定义。空节点数组表示明确的空应用声明，不意味着云 DAG 为空。

Limits are 128 nodes and 256 KiB. Unknown fields, duplicates, unknown Workers, cycles, foreign tenants and stale inventory are rejected. Never include passwords, API Keys, message bodies, scripts or business inputs. An empty node array is an explicit empty application declaration, not evidence of an empty cloud DAG.

## 保存和双向同步 / Save and bidirectional sync

1. 选择“保存本地声明”，确认声明归应用所有，点击“验证 DAG 并预览差异”。预览只读比较，不创建永久请求事实。
2. 审阅新增/移除/变化节点、基线版本和候选接收端状态，点击提交并再次明确确认。只有这一次 PUT 提交候选内容。
3. 初次接收端为**未知**。保存成功后选择“同步 Mock 接收端”，人工选择方向并勾选 Mock 专用确认，重新预览和提交。

1. Choose “Save local declaration,” confirm application ownership, and validate/preview. Preview only compares; it creates no permanent intent fact.
2. Review added/removed/changed nodes, baseline revision and candidate receiver state, then commit with explicit confirmation. Only that PUT commits the candidate.
3. The receiver is initially **unknown**. After saving, choose “Sync the Mock receiver,” select a direction, confirm Mock-only sync, then preview/commit again.

| 方向 / Direction | 实际结果 / Result |
|---|---|
| Push | 已保存本地 → 独立应用 Mock 接收端 / Saved local → separate application Mock receiver |
| Pull | 已知 Mock 接收端 → 本地；未知接收端返回412 / Known Mock receiver → local; unknown returns 412 |
| Both | 本地优先写接收端；不冒称厂商冲突合并 / Local wins and updates receiver; no claim of vendor conflict merging |

接收端仅存储在本平台当前租户的独立配置记录，不在厂商，也不会驱动业务消费者。`providerCalled=false`，`consumerApplied=null`。保存/同步产生一个新版本和唯一成功审计；原 UUID 的回执永不替换成当前定义。

The receiver is stored in a separate configuration record for the current platform tenant, not at the vendor, and does not drive a business consumer. `providerCalled=false`, `consumerApplied=null`. Save/sync creates a new revision and one success audit; an original UUID receipt is never replaced with the current definition.

## 冲突、超时及来源变化 / Conflict, timeout and source change

409 保留文本、确认及旧基线。人工点击 GET 重读比较不会覆盖草稿；点击“明确采用已读基线”并确认，才替换版本/来源标识，同时保留节点并清除确认。之后需要重新勾选、预览、人工提交新 UUID。

A 409 retains text, confirmation and the old baseline. Manual GET comparison never overwrites the draft. Explicit adoption replaces revision/source identity, retains nodes and clears confirmations. Reconfirm, preview and manually submit a new UUID.

断线、408、5xx 或无法核验的2xx可能已经提交：界面保留原 UUID/内容并锁定新写入，允许发送 GET 读取原回执。404 **不能**证明未提交，不能解锁重发。已核验原提交或明确4xx拒绝后，人工开始新动作；新动作不会自动采用当前版本。切租户或会话会清除旧视图，不把旧响应带入新组织。

Disconnects, 408, 5xx and unverifiable 2xx may follow a commit: the UI retains the original UUID/body and locks new writes, while allowing original-receipt GETs. A 404 **cannot** prove no commit and never unlocks resubmission. After a verified fact or explicit 4xx rejection, begin a new action manually; it does not adopt the current revision automatically. Tenant/session changes discard old views and responses.

配置、Team 成员、角色元数据或映射资产变化会使来源过期。需要 GET 比较、明确采用当前库存，再选择新保存并确认清空旧 Mock 接收端。不能用旧来源继续 Pull/Push/Both。停用连接或切到 Live 后，原回执仍可只读查询，不重新派发。

Configuration, membership, role metadata or mapped-asset changes make the source stale. Compare via GET, explicitly adopt current inventory, then save anew with confirmation to clear the old Mock receiver. Old-source Pull/Push/Both is rejected. Original receipts remain readable after disable or switching to Live, without redispatch.

## 企业与个人部署 / Enterprise and personal deployment

企业启用现有 PostgreSQL 后，定义/原请求采用租户 RLS 和 AEAD 保存，并与成功审计同一事务提交，支持双实例读取与原 UUID 去重。个人无数据库部署走当前进程内存的同锁提交，进程重启不保证保留回执，不能称跨实例持久。

With the existing PostgreSQL deployment, tenant RLS and AEAD protect definitions/intents, committed in the same transaction as success audit, with cross-instance reads and UUID deduplication. A personal deployment without a database uses same-lock process memory and has no restart or cross-instance durability guarantee.

每租户最多64 Team、512永久请求、解密后配置3MiB。满额拒绝新提交；不后台淘汰事实、不提供删除解锁。查看库内存/数据库边界及容量计数再规划长期使用。

Limits are 64 Teams, 512 permanent intents and 3 MiB of decrypted configuration per tenant. Full capacity rejects new commits without background eviction or delete-to-unlock. Review durability and capacity counters before long-term use.

## 三种现有应用接入模式 / Three existing-application integration modes

**侧车/配置发现**：打开 `/agents` 的纳管向导，选择运行环境与受支持客户端，预览发现的配置，再手动确认连接。终端宿主的 `AGF_AGENT_PROJECT_ROOTS` 只列自己授权的绝对目录（最多8项）；不复制包含秘密的环境。发现配置不等于所有流量被接管。详见 [Agent接入指南](agent-onboarding-guide.md) 与 [本地闭环验证](local-onboarding-smoke.md)。

**Sidecar/configuration discovery**: use the onboarding wizard at `/agents`, select the runtime/supported client, review discovered configuration and finish the connection manually. `AGF_AGENT_PROJECT_ROOTS` on the terminal host contains only authorized absolute roots (up to eight). Never copy secret environment values. Discovery is not proof of traffic interception. See the linked onboarding and local-smoke guides.

**SDK显式接入**：按 [Python SDK](../sdk/agentteams/python/README.md) 或 [Node SDK](../sdk/agentteams/node/README.md) 设置真实遥测源、已盘点 Worker 绑定和来源 scope，显式装饰/包裹业务调用。这需要应用接入，不是零改造自动注入。`sources:write` Key 是租户级而非源级授权；Key 只存秘密配置。遥测队列重投不重新执行业务。本地编排定义不自动生成 SDK 执行器。

**Explicit SDK integration**: follow the Python or Node SDK README to configure a real telemetry source, inventoried Worker binding and source scope, then explicitly decorate/wrap business calls. This requires application integration, not automatic zero-change injection. A `sources:write` Key is tenant-wide rather than source-scoped; store it only in secret configuration. Telemetry redelivery never reexecutes business. Local declarations do not generate SDK executors.

**网关配置**：在 `/models` 创建/核对模型端点，在设置中创建权限最小且绑定正确 Agent 的 Key，使用支持 Base URL/模型/Key 配置的客户端连接本平台兼容网关。若客户端不能改地址/配置，本功能不能自动拦截它。执行权限仍取原 Key scopes 与已纳管平台 Role 权限的交集，编排声明不扩权。详见 [模型使用指南](model-usage-guide.md) 与 [Claude Code 网关配置](claude-code-gateway.md)。

**Gateway configuration**: create/review model endpoints at `/models`, create a least-privilege Key bound to the correct Agent in settings, and configure a client that supports Base URL/model/Key for the compatible gateway. Unsupported clients are not automatically intercepted. Execution permissions remain the intersection of original Key scopes and governed platform Role permissions; declarations grant no authority.

三个模式均须按实际客户端能力完成连接并验证真实请求/审计；保存编排声明本身不证明免改造接管、真实厂商部署、消费者执行或业务重放完成。

All modes require connection setup and actual request/audit verification for the client in use. Saving declarations alone proves none of automatic onboarding, vendor deployment, consumer execution or business replay.
