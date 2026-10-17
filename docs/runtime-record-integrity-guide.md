# MCP 运行时已保存事实的完整性边界

`POST /api/v1/runtime/mcp/check` 以及复用同一判定入口的 MCP HTTP/SSE 代理，保存新 `runtime-interception` 记录时，将完整记录的规范化 SHA-256 摘要及脱敏管理审计一起提交。该事实表示策略判定已保存，不能证明上游已经执行、成功或被操作系统阻断。请求级租约只在判定事实提交后创建；完成响应保存失败时，原并发租约和工具用量仍按失败关闭，不返回允许响应。

PostgreSQL 使用既有租户治理事务、配置编号锁及管理审计链锁，记录与审计失败一起回滚。相同记录编号只能重试原内容及原保存证明，且持锁确认精确管理审计仍存在；不重复追加管理审计。不同内容、被删改的证明或旧无证明记录均冲突，不覆盖或补造历史认证。记录编号与 JSON-RPC 请求编号不同，本功能不承诺重复发送同一 JSON-RPC frame 只产生一条新判定。

离线 Mock 使用同一个 ConfigStore 内存锁完成保存条件检查、同步审计和插入，失败不发布候选；原证明核对也在此锁内执行。它只保证进程内原子性，不能跨重启持久保存。跨实例与重启的持久合同只适用于 PostgreSQL 部署。

摘要输入为完整 `InterceptionRecord` JSON，递归按对象键排序、数组保留次序、使用紧凑 UTF-8 JSON 编码，再做 SHA-256；不包含内部 `_agf_management_audit_v1` 证明字段。保存预算为 64 KiB。管理审计仅包含固定 schema、记录编号、SHA、Agent 编号、拦截点、动作、处置及 enforced，不包含原载荷、工具名、会话名、路径、策略原因或摘录。管理审计编号由用途域、认证租户及记录编号派生，不能由客户端指定。

保存前使用既有 Actor 当前主体/权限解析；SQL 审计等待后的提交前重查复用原 AssetTransaction，不持有一条连接再向同池借第二条。目标租户仍由原事务核验 enabled/墓碑；SQL 用户、角色绑定、Key、Agent、MFA 和 AgentTeams 治理事实在同一事务中读取并加共享行锁，等待后再过滤自然过期的角色绑定和 Key，并核对原身份、租户及绑定 Agent。身份租户上下文仅来自认证结果，读取个人账号与 MFA 后恢复业务租户。它不重新验证原 JWT 等待期间的 exp 或登录会话，也不宣称重新运行已经完成的全部策略判定。离线当前权限解析在获取 ConfigStore 锁前执行。

事务内账号权威必须由 AuthBackend 显式声明：内置 SQL 后端只接受与业务事务相同的 Store；内置同步内存后端在用户与角色锁共同持有时返回一致快照，并在 MFA SQL 等待后重新读取。账号缺失或撤权不能回退到 SQL 或旧 Principal。同步快照不承诺内存锁贯穿异步 SQL commit。ProtectedBackend 的 MFA 配置也必须与该事务使用同一 SQL Store，不能把内存或另一库的配置静默当成未启用 MFA。自定义异步身份后端默认不具备此能力，MCP SQL 事实提交明确拒绝；不改变其他路由的身份来源。现有 SQL 业务库加内存账号、同 SQL 配置的混合装配仍受支持。

## 有界单条读取

`GET /api/v1/runtime/events/{id}/integrity` 要求 `policies:read`，租户来自认证。每次只读一条配置及派生的精确审计编号，SQL 在同一事务内锁定原记录和审计行，JSONB 文本超过 128 KiB 时直接返回不匹配哨兵而不传回异常大对象；该读取上限兼容 64 KiB 紧凑记录的 JSONB 空白编码。离线在同一配置锁内核对。不会追加审计、建立检查点或扫描整条租户链。

响应保留 `record_id`、`status`、`summary_matches`、`checkpoint_verified`、`checkpoint_verification_path`，匹配成功时才返回 `record_sha256`、`audit_id`、`audit_sequence`、`audit_entry_hash`。

| status | summary_matches | 含义 |
|---|---|---|
| missing-record | false | 当前租户没有该持久事实，包括仅在诊断环形缓冲区的记录 |
| missing-proof | false | 保存证明缺失；不回退成可信旧格式 |
| mismatch | false | 记录、内部证明或精确管理审计不匹配，或管理审计缺失 |
| matched-management-fact | true | 完整记录与该次已提交管理审计摘要相匹配 |

`checkpoint_verified` 始终为 **false**。摘要匹配不等于签名锚定：具有 `audit:read` 权限的调用者还须读取 `/api/v1/audit/verify`，验证管理链、签名检查点和项目数据目录外部见证，并核对其覆盖序号至少达到该 `audit_sequence`。若只有配置记录被改写，管理审计及签名检查点可能仍有效；本单条比对会发现两者不再匹配。若管理审计也被重算，全链/外部见证验证负责发现该情况。

原 `GET /api/v1/runtime/events` 裸数组和字段投影保持兼容。该视图合并持久记录与诊断环形缓冲区，不能据此把每一行宣称为已持久或已签名；本新增合同不会静默过滤旧记录，也不把所有 SDK/runtime lane 都纳入此证明。进程准入记录由其独立回执与管理审计合同保护，不借此 MCP 保存证明冒充统一链。

## 回归与本轮限制

普通 target `runtime_audit_persistence` 使用真实认证、正式 MCP 路由、公开 events/integrity 读取及 OpenAPI，覆盖同编号并发、改写、证明删除和合法 API Key。

ignored SQL target `runtime_audit_persistence_database` 复用 `audit_anchor_database_support::Owned` 的精确独占库、COMMENT/OID/owner 和数据目录围栏，四例验证真实路由与重启、配置重算/证明删改、审计故障前后租约清理、双实例并发和跨租户隔离，并显式使用生产 SQL 身份后端。原四个用例名称不变，增量验证同步内存身份混合装配、8 连接池占用 7 条后 SQL 用户与绑定 Key 的保存及精确重试、实际等待审计 advisory 锁期间撤 Key 后不提交且不返回允许。只能由拥有精确 fixture 的最终 SQL runner 执行，不能指向正式数据库。

此候选尚未运行 Cargo、普通或 SQL 测试；编译、格式、实际测试和完整项目验收结果须以最终源对应 receipt 为准。
