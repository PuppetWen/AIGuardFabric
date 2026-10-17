# Multi-target red-team chain / 多目标红队链路

Select two different registered Agent HTTP profiles and one registered MCP HTTP profile. The fixed three-step playbook reads a reference from Agent A, passes a sanitized reference to one explicitly configured read-only MCP tool, then asks Agent B to summarize the returned context. No uploaded YAML, arbitrary shell, business replay or implicit seed target is accepted. Single-target campaigns keep their existing behavior.

选择两个不同的已登记 Agent HTTP 配置及一个 MCP HTTP 配置。固定三步剧本从 Agent A 读取引用，将净化后的引用交给明确配置的一个 MCP 只读工具，再由 Agent B 总结返回上下文。不接受上传 YAML、任意 shell、业务重放或隐式种子目标；原单目标战役保持原行为。

## Register and review / 登记与审阅

1. Use Assets to register the real Agent and MCP assets. In Red Team → Agent target configuration / MCP target configuration, save each exact URL, model/tool and profile version. Configure a dedicated nonsecret canary in both the target context and profile. Credentials and canaries remain encrypted with tenant/profile AAD.
2. Reading requires current `redteam:read`, `agents:read` and `mcps:read`. Executing, cancelling, recovering and archiving additionally require current `redteam:execute` and the original identity. Target registration keeps its existing write permissions. A durable PostgreSQL backend is required for execution and transport approval.
3. Select all three targets explicitly, preview the fixed topology and exact versions, then confirm the registered read requests. A tool annotated read-only can still consume quota. It must be unique and require exactly the configured string argument. At most four complete tool-list pages with up to 128 tools per page (at most 512 across four pages) are accepted; incomplete or unsupported inventories stop before `tools/call`.

1. 在资产台账登记实际 Agent 和 MCP，再在红队目标配置保存准确 URL、模型/工具及配置版本。在目标上下文和配置中使用相同的专用非秘密哨兵；凭据和哨兵按租户/配置 AAD 加密。
2. 读取需要当前 `redteam:read`、`agents:read`、`mcps:read`；执行、取消、恢复、归档另需当前 `redteam:execute`，且必须是原身份。目标登记沿用原写权限；执行及传输批准需要持久 PostgreSQL。
3. 必须手动选择全部目标，审阅固定拓扑和准确版本后确认读取。只读工具仍可能消耗配额；工具必须唯一且仅要求准确指定的字符串参数。清单最多四个完整分页，每页最多 128 个工具（四页合计最多 512 个）；不完整或不支持的清单在工具调用前停止。

## MCP protocol / MCP 协议

The default is the explicit `2026-07-28` Streamable HTTP revision. Every request carries the required protocol/method headers and complete client `_meta`; tool calls also carry the tool-name header. Both JSON and SSE are accepted. Request-scoped SSE is limited to 64 KiB and 128 events; progress notifications are ignored, while server requests, mismatched IDs, multiple final results and incomplete framing are rejected. There is no GET stream, reconnection, resume or automatic request retry. See the [modern transport specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).

A platform administrator can explicitly select `2025-11-25` for a registered MCP profile. This performs `initialize` → `notifications/initialized` before listing/calling, validates the exact negotiated revision and retains the returned session only in memory for this run. Session rotation, unsupported negotiation or invalid notification acknowledgement stops the run. It never renegotiates or repeats a tool call. See [legacy transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) and [lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle).

A single direct string-property `x-mcp-header` with a bounded valid token is supported as `Mcp-Param-<token>`. Values requiring encoding use the specified UTF-8 base64 sentinel, including values that already resemble that sentinel. Nested/composed, nonstring, multiple or invalid annotations stop before the tool call with `mcp_contract_unsupported`; select a compatible explicitly read-only tool. No prompt or header value is stored in evidence.

默认明确使用 `2026-07-28` Streamable HTTP。每个请求提供协议/方法头及完整客户端 `_meta`，工具调用提供工具名头，同时接受 JSON 和 SSE。请求内 SSE 限制 64 KiB、128 个事件；忽略进度通知，拒绝服务端请求、错误 ID、重复终态及不完整帧。不建立 GET 流、不重连、不续流、不自动重试。

平台管理员可以为真实 MCP 配置明确选择 `2025-11-25`。先完成初始化与 initialized 通知，再列出/调用工具；核对准确协商版本，返回的 session 只在本次运行内存中存在。session 改变、不支持的协商或错误通知确认均停止；不会重新协商或重发工具调用。

支持一个直接字符串字段上的合法有界 `x-mcp-header`，映射到 `Mcp-Param-<token>`，必要时按规定使用 UTF-8 base64 哨兵编码。嵌套/组合、非字符串、多处或错误注解会在工具调用前停止，原因是 `mcp_contract_unsupported`；需选择受支持的明确只读工具。证据不保存提示词或头值。

## Enterprise private access / 企业私网接入

Without approval, targets require credential-free public HTTPS, and every resolved address must be public. Proxy use and redirects are disabled. There is no global private-network switch. To approve a private target, a current normal User with `platform:admin`, `redteam:execute`, `agents:read` and `mcps:read` opens **Managed transport** for the exact registered profile. Keys cannot administer this approval.

Read the actual profile version and URL, specify the complete set of RFC1918 IPv4 or ULA IPv6 addresses and one exact port, then explicitly confirm the network. Private HTTPS and private HTTP are supported; HTTP needs the additional **Allow plain HTTP** consent. Loopback, link-local, metadata and public addresses cannot appear in a private approval. DNS answers must match the complete approved set, with no added or missing address, and the client pins the chosen address. Literal addresses must match as well. The approval is encrypted and bound to tenant, target kind/profile, actual profile version, URL, approval CAS version and network settings. No DNS or target request occurs when saving approval.

A profile change, disabled approval, changed DNS answer, port mismatch or approval CAS conflict blocks execution. Comparison GET retains the draft and original baseline; adopting the latest baseline and saving are separate manual actions. A PrivateLink inventory status of Connected is not evidence of TCP reachability or successful Agent/MCP processing. Configure and verify the actual target separately.

无批准时仅允许无内嵌凭据的公共 HTTPS，所有解析地址必须为公网；禁代理和跳转，没有全局私网开关。当前普通 User 具备上述管理员和红队权限后，在 **Managed transport** 选择准确已登记配置；Key 不能管理批准。

读取真实配置版本和 URL，提供全部 RFC1918 IPv4 或 ULA IPv6 地址及一个准确端口，显式确认网络。私网 HTTPS 和 HTTP 均支持，HTTP 另需明确允许明文。批准不能包含回环、链路本地、元数据或公网地址。DNS 全部地址必须与批准集合完全一致，禁止新增、遗漏或混入，客户端固定选定地址；字面地址也必须准确匹配。加密批准绑定租户、目标种类/配置、实际版本、URL、CAS 版本和网络；保存时不做 DNS 或目标请求。

配置变版、停用批准、DNS 变化、端口不符或批准 CAS 冲突都会阻断。比较 GET 保留草稿和旧基线，采用新版与保存均为独立手动动作。PrivateLink 的 Connected 不能证明 TCP 可达或 Agent/MCP 处理成功，需另行验证实际目标。

## Original UUID, recovery and archive / 原 UUID、恢复与归档

The UI holds one generated UUID and exact body before sending. Same-body POST replay and GET return the original local fact; changed-body reuse is 409. A lost response, 404 or an unrelated historical complete receipt never unlocks that pending intent. Every outbound request rechecks the original current identity, session/JWT/Key, roles, tenant, profile/asset/approval and cancellation under the original 110-second deadline. Already-sent reads cannot be undone.

**Load my recent UUIDs** is a manual pure GET over at most 256 recent IDs for the original owner, with pages of 20 (API maximum 50). It does not dispatch, seed, change SQL or append audit. Historical selection only reads that UUID and cannot release another unknown intent. After refresh, choose the original recent UUID or enter an older saved UUID manually. Save original IDs in an operator record; this bounded list is not a complete tenant history. Other owners cannot enumerate these IDs.

Known results are staged encrypted. If terminal publication fails, **Recover local publication** sends only `{}` and publishes the original evidence with no provider/STS call. Current-source changes do not replace the original topology. Expired interrupted runs can only be locally finalized as failed; there is no continuation. Cancelling prevents later steps. Different administrators cannot replace the original owner.

A tenant has at most **128 unarchived bodies** and **16,384 permanent request facts**. Archive only after a known terminal publication, reviewing its generation. Archive removes the body evidence, retains its digest, original input identity, findings, terminal audit and UUID, and appends one real tenant Update audit. The same reviewed generation is a pure no-op; a different generation is 409. Archive never grants dispatch for the old UUID. A new explicit intent can use a freed body slot, but permanent capacity never decreases. At the permanent limit, stop new campaigns in this namespace and use existing UUIDs for reading/local handling; neither deletion, identity switching nor archival is a supported reset. No automatic eviction exists.

界面发送前固定 UUID 与正文。相同正文重放和 GET 只读原事实；同 UUID 更换正文返回 409。丢响应、404 或另一个历史已完成回执都不能解锁当前未知意图。每次外发按原 110 秒期限重验原当前身份、会话/JWT/Key、角色、租户、配置/资产/批准和取消；已发送的读取不能撤回。

**Load my recent UUIDs** 手动纯 GET 原所有者最近最多 256 个 UUID，每页 20 个（API 最大 50）；不派发、初始化、改 SQL 或写审计。选择历史 UUID 不解锁另一未知意图。刷新后选原近期 UUID，或手动输入已保存的更早 UUID；需保留操作记录，这不是完整租户历史。其他所有者不能枚举这些 ID。

已知结果加密暂存；终态发布失败时“恢复本地发布”只提交 `{}`，不调用目标/STS。来源变更不替换原拓扑。到期中断只能本地结为失败，不继续执行；取消阻止后续步骤，其他管理员不能替代原所有者。

每租户最多 **128 个未归档正文、16,384 个永久事实**。仅在已知终态发布后按审阅代次归档，清正文证据但保摘要、原输入身份、发现、终态审计和 UUID，并追加真实租户 Update 审计。相同审阅代次纯 no-op，其他代次返回 409。归档永不让旧 UUID 再派发；新明确意图可使用释放的正文槽，但永久容量不减少。永久上限后停止该命名空间的新战役，仅处理旧 UUID；删除、换身份、归档均不是受支持的重置方式，没有自动淘汰。

## Evidence and stage-one boundary / 证据与阶段一边界

Completed means all three actual response contracts completed. `defensePassed` is true only after all actual responses were evaluated and no configured canary was found; null is unverified, including archived body evidence. Findings, permanent terminal fact and Execute audit publish in one transaction. Existing MCP quota/usage remains its existing separate subsystem; this feature does not claim quota settlement atomicity. Raw prompts, bodies, bearer tokens, sessions and canaries are not returned or stored. Relay text is memory-only, redacted and capped at 256 UTF-8 bytes. Transport proof is an opaque digest of the actual approved/pinned addresses and request origin, not a TCP probe or universal security claim.

Definitions for stage one use actual owned literal127 servers through a default-off test feature, real platform HTTP and exclusively owned PostgreSQL. RFC1918/ULA approval validation uses real address types with no enterprise network calls; literal127 is a controlled test analogy, never a production private approval. These unexecuted definitions are not real-cloud acceptance or phase-two credential evidence.

Completed 表示三步实际响应契约完成；只有全部真实响应已评估且未发现哨兵才为 `defensePassed=true`，null 表示未验证，归档正文也不伪称已验证。发现、永久终态事实和 Execute 审计同事务发布；既有 MCP 配额/用量仍属原独立子系统。不返回或保存原提示词、正文、令牌、session 或哨兵；转交文本仅在内存，先净化再限制 256 UTF-8 字节。传输证明只是实际批准/固定地址和来源的摘要，不是 TCP 探针或全面安全证明。

阶段一定义使用默认关闭测试 feature 的实际专属 literal127 服务、真实平台 HTTP 和独占 PostgreSQL。RFC1918/ULA 批准验证不请求企业网络，literal127 只是受控类比，不能作为生产私网批准。尚未执行的定义不能称真实云验收或阶段二凭据证明。
