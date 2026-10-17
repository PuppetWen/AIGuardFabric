# AgentTeams 本地角色约束（候选，尚未部署）

这项约束把已盘点 Worker 的已观察云 Role 与实际平台角色关联。
云 Role 字符串只用来匹配管理员审查的关系，不是登录凭据，也不会在阿里云新增权限。
Worker 使用绑定到同租户 Agent 的平台 API Key 时，有效权限是 **Key 原 scopes 与平台角色权限的交集**。
平台用户、未绑定 Agent 的 Key、未采用角色约束的 Agent 保持现有授权方式。

## 前置条件

本候选的管理需要 PostgreSQL。现有离线认证只保存角色名，不能提供可信角色 UUID。
离线读取会明确 `catalogAvailable=false`，不返回假角色、不自动生成授权；离线新增映射尚未实现。
已治理 Agent 的目录或约束记录缺失时拒绝调用，不恢复原宽 scopes。

管理员必须使用仍有效的用户会话，同时拥有 `platform:admin`、`alicloud:read`、`assets:write`。
完整云盘点另需现有 `alicloud:write`。本功能只写本地治理记录与审计，不自动调用云端。
这里只选择本租户 `roles` 表的实际记录，与“用户管理”中当前角色分配使用同一目录。
目录中尚无所需角色时先在现有用户管理中配置合法角色；本功能不创建另一套角色数据。
旧适配器的 operator/viewer/auditor 推测只有 `role_mapping_hints`，不能当真实角色或权限。
管理列表的 `mappedCount` 仅计入已提交且当前 Role、来源、成员、Agent 证明仍有效的约束；
原不可变回执不证明今日资格，`currentQualified=null` 表示该回执没有执行当前资格核验。

支持实际已保存的 tenant-admin、soc-analyst、redteam-engineer、auditor、viewer 内置角色。
权限定义必须与当前服务验证的内置定义一致。未验证的自定义角色明确不可采用。
superadmin 涉及用户与跨租户语义、asset-owner 涉及部门资源 ABAC，本期不把它们转换成普通 Key 权限。
部门与数据分级仍作为已采用 Agent 身份证明的一部分核验；改变后原约束失效，需要重新审查。

## 采用与停用

1. 在云连接配置 AgentTeams 账号、区域、实例与模式。先启用连接，再由用户手动完整盘点。
2. GET `/api/v1/alicloud/agentteams/role-mappings` 读取真实角色及已盘点 Worker/Team/CloudRole。
   未提供 Role 时是未知，不能采用。Worker 资产 UUID 必须来自当前盘点。
3. 管理员确认本地权限约束，向 `/role-mappings/{assetId}` 发 PUT：
   `request_id` 是新的 UUID，`expected_version` 是当前映射版本（首次 0），
   `confirm_local_constraint=true`，`change.action=adopt`。
   change 必须携带 `configuration_version`、`observed_at`、`worker_name`、`team_name`、`cloud_role`、`role_id`。
   不能提交自定义 permissions，也不能靠云 Role 名称推断平台角色。
4. 创建 Key 时选择该 Agent 的 `bound_agent_id`，指定真实所需 scopes；不会自动增加 scopes。
   Key 原始记录仍保留，以便管理员核查；运行时使用交集，而非把 Role 权限叠加到 Key。
5. 停用用新的 UUID、当前 `expected_version`，`change.action=disable`，仍要明确确认。
   即使云连接或 Worker 已停用/删除，也可保留本地停用事实；不会复活资产。

采用需要 300 秒内的完整观察，审计等待后也检查这个门槛。
已采用有效约束不因此五分钟后自动失效；运行时核当前来源、成员 Role、角色定义和 Agent 身份。
完整盘点发现成员移除、Role 改变或来源变更，会同事务记录 revoked/unverified 并增加 CAS 版本。
后来的正面观察不会自动恢复。必须新盘点、管理员重新审查并明确采用。

## 冲突、回执与故障

409 表示映射/盘点版本或原请求用途改变。保留草稿，先读取当前信息，明确选用后再创建新意图。
请求响应丢失时读取 `/role-mappings/{assetId}/requests/{requestId}`；GET 不重派、不调用云端、不新增成功审计。
相同身份、Worker、请求编号与原完整 body 重发只返回原不可变事实，不再次授权或审计。
把相同请求编号改用于 Adopt/Disable、另一 Worker 或另一管理员会返回 409。
原回执的版本不代表当前仍启用；当前状态应另外读取 `/role-mappings/{assetId}`。

映射、Agent 永久标记、不可变意图和成功审计同 SQL 事务提交。
失败不会留下可用权限或成功审计。管理员会话、当前权限和原访问令牌在审计等待后复查。
单独删除映射正文/永久标记不恢复宽 scopes；本 API 没有删除接口。
最多 512 个治理 Worker、2048 个永久意图，每条加密记录最多 128 KiB。
不后台清除永久事实；容量满时明确拒绝新意图。跨实例以 SQL 为准，不能把内存缓存当授权依据。

这不是厂商 Role 写入、云端登录授权或任务重放；本候选未实现离线新增角色映射、控制台入口、
OpenAPI 展示或全阶段一完成证明。库/HTTP/SQL 测试目前只已定义，等待父任务在 1.2 实际运行。

## English operating boundaries

Use a current administrator user session and the actual tenant SQL role directory. Explicitly inspect inventory,
choose the Worker asset and its observed Team/cloud role, choose a supported platform role UUID, then confirm
an `adopt` PUT with the current CAS version and a new intent UUID. A bound Key receives the intersection of
its own scopes and the selected role; cloud role names never authenticate or grant permissions.

`disable` preserves the permanent governed identity. Missing, disabled, stale or revoked constraints fail closed.
Complete negative inventory evidence is sticky. Fresh positive evidence needs a new explicit adoption, not an
automatic permission restoration. The 300-second observation window applies to human adoption, not daily runtime TTL.

For a lost response, read the original intent receipt first. GET is local and read-only. A receipt records the
original fact, not today's eligibility. CAS conflicts preserve the reviewed intent; no automatic version change
or cloud retry is implied. SQL role definitions, mappings, marker and success audit are checked transactionally.
Offline creation, console integration and vendor role writes are not implemented by this candidate.
Legacy adapter name guesses are review hints only. The current mapping count verifies committed constraints
against the actual role catalog, source, membership and Agent identity; an immutable receipt is historical evidence.
