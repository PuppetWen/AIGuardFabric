# MCP HTTP 接入指南

## 个人接入

1. 打开 **MCP 管理 → HTTP 接入配置 → 新增 MCP 端点**。
2. 选择传输协议。Streamable HTTP 填原服务的 `https://mcp.example.com/mcp`；2024-11-05 HTTP+SSE 填其接收流 `https://mcp.example.com/sse`。地址必须能被平台服务器访问；容器内的 `127.0.0.1` 指容器自身。URL 不接受内嵌用户名、口令或查询参数。固定 Bearer token 单独填写并加密保存；若上游要求 OAuth，先不填固定 token，保存端点后按下文授权。更换目标地址时必须重新填写固定 token，或显式清空旧 token。
3. 启用并保存。在“连接指南”选择上游支持的协议版本，执行“检测连接与工具列表”。检查只进行服务发现和工具列表读取，不执行工具。2024 SSE 和 2025 HTTP 使用 initialize；2026-07-28 使用 server/discover。2024 SSE 探测会核对服务端公告的 POST 地址与配置的上游同源，避免把上游凭据发往另一站点。
4. 点击连接指南中的“前往创建平台 API Key”，进入“设置 → API Key”，新建密钥时只勾选 `mcps:execute`、`policies:read`。创建框不预选其它权限，完整密钥只显示一次，请立即安全保存。这个密钥认证到平台；上一步的 token 认证到原服务。
5. 在连接指南选择 Claude Code 或 Cursor，填写客户端可访问的平台地址，复制或下载配置模板。Streamable HTTP 代理路径为 `/api/v1/mcp/proxy/<端点 ID>`；2024 SSE 路径为 `/api/v1/mcp/legacy/<端点 ID>/sse`。同源控制台地址、API 端口和独立 MCP 端口均可使用。
6. 将模板中的 `mcpServers` 条目合并到项目配置。Claude Code 使用 `.mcp.json`，启动前设置 `AGF_MCP_KEY`；Cursor 使用 `.cursor/mcp.json`，在本地替换平台密钥占位符。不要把实际密钥提交到仓库。
7. 重启或刷新客户端连接，检查服务和工具列表。先调用只读工具，再添加一条测试运行时黑名单，确认命中调用被平台拒绝且上游未执行。

本地 stdio 服务继续使用接入指南中的 `agf-agent mcp-proxy -- 原命令 参数`。2024 双端点 SSE 会在客户端连接平台代理 `/sse` 后，向它公告平台代理 POST 消息地址；客户端只需配置一个 `/sse` 地址，不应手工填写上游 `/messages` 或上游 token。平台分别处理这个旧传输和 2025/2026 Streamable HTTP。

探测会读取全部工具分页（最多 32 页、5000 个工具、累计 4 MiB）。成功后工具清单和服务版本持久保存，MCP 管理及资产详情可查看；刷新或服务重启后仍然保留。重复游标、工具重名及超出上限会报错，不会把截断的清单当成完整结果。修改端点后旧清单失效，请重新探测。

## 企业接入

- 管理员集中登记原服务地址及上游凭据，将生成的代理配置通过现有终端管理系统下发。按 Agent 发放并绑定平台密钥，撤销某个密钥不影响其他员工；租户由认证密钥决定。
- 生产使用 HTTPS 入口。反向代理应关闭 MCP 路径的响应缓冲，读取超时应超过端点空闲超时；保留 `MCP-Protocol-Version`、`Mcp-Method`、`Mcp-Name`、`Mcp-Param-*` 和传统会话头。2024 SSE 的 GET 流与随后 POST 消息必须由同一客户端身份和租户访问；平台会持久保存随机会话绑定，支持多实例。不能在中间层自动重试 `tools/call`。
- 主服务提供独立 MCP 端口。Compose 中 `agf-server` 容器内监听 `AGF_MCP_PROXY_PORT=8091`，宿主机默认映射到 `AGF_MCP_PROXY_HOST_PORT=8092`，避开宿主机上可能已被占用的 8091。客户端从局域网连接 `http://localhost:8092/api/v1/mcp/proxy/<端点 ID>`；经 HTTPS 入口时使用该入口的域名和路径。手动运行主服务时未设置监听变量默认不启动独立端口；设为 `0` 关闭独立端口，API 内 MCP 路由仍可用。
- Helm 通过 `ports.mcpProxy` 统一设置主服务监听、Service 和容器端口。启用网络策略时，确保 MCP 客户端经允许的 Ingress/命名空间访问，并为实际 MCP 上游增加必要的出站规则。
- 命令行客户端不需要 Origin。浏览器客户端必须在端点中登记精确来源，例如 `https://console.example.com`，并在 `AGF_CORS_ALLOW_ORIGINS` 配置同一来源。端点来源不接受通配符、路径、`null` 或末尾斜线。带自定义 Mcp-Param 头的浏览器客户端使用独立 MCP 端口或其 HTTPS 反向代理。
- 修改端点使用版本检查；409 时草稿保留，先查看服务器最新版本，比较后再选择沿用新版本号保存。端点配置版本改变会使已有传统会话失效，客户端需重新连接。
- PostgreSQL 部署中，保存端点会在同一租户事务提交配置、MCP 资产投影和成功审计；任一写入失败时均不发布新版本。离线内存模式用于本地模拟，不保证跨存储原子性。

## 运行行为与排障

| 现象 | 检查及处理 |
|---|---|
| 401 | 平台 API Key 是否正确、过期或已撤销；不要把上游 token 填到客户端平台代理头 |
| 403 | mcps:execute / policies:read 权限、Origin、Agent 身份及运行时策略 |
| HTTP 代理 502 且提示上游 401 | 平台已收到上游鉴权拒绝；由管理员更新端点中保存的 Bearer token，再执行只读探测。代理不会把上游登录挑战、错误正文或凭据返回客户端 |
| HTTP 代理 502 且提示上游 403 | 核对上游 token 的目标受众及工具权限；先用原服务的只读工具列表验证授权范围 |
| HTTP 代理 502 且提示上游非 JSON 或响应 ID 不匹配 | 核对目标地址、协议版本和上游服务日志；平台拒绝把非 JSON-RPC 内容当工具结果，不回显上游正文 |
| HTTP 代理 502 且提示上游错误状态 | 核对原服务的地址、健康与日志；即使上游返回合法 JSON-RPC 错误，代理也不回显其错误正文或内部诊断 |
| HTTP/SSE 返回 200 但 JSON-RPC 内含 error | 这是上游协议级拒绝；客户端只收到数字错误码和平台固定提示。按错误码及上游日志排障，平台不会转发原始 message/data |
| 只读探测提示上游拒绝并显示 JSON-RPC 错误码 | 按错误码核对服务所支持的协议与发现方法，再查上游权限和日志；控制台只显示数字错误码，不显示上游错误消息或附带数据 |
| 404 会话 | 会话属于原调用者和原配置版本；2024 SSE 流失效或端点修改后重连，重新 initialize |
| 412 | 端点停用；请管理员启用 |
| 429 | 查看错误信息区分平台租户/Agent/会话配额和原 MCP 服务的限流；原服务的私有响应不会回显 |
| HeaderMismatch / -32020 | 2026 请求中的版本、方法和名称 HTTP 头须与 JSON-RPC 参数一致 |
| 原服务返回 400/404/405 后代理 502 | 选择正确协议及最终端点路径；旧版会话失效仍以安全的 404 提示重建，代理不会追踪跳转或自动重复工具调用 |
| 超时或连接错误 | 检查平台到上游的 DNS、路由、防火墙、TLS 信任链及端点空闲超时 |
| 探测成功但会话关闭未确认 | 上游未实现或拒绝 DELETE；临时传统会话最长保留一小时 |

所有 JSON 响应和 SSE 的 JSON-RPC 消息都经过运行时检查；响应脱敏后才交付客户端。单帧最大 1 MiB，空闲超时可设 5..600 秒，活跃流持续续期配额。2024 SSE 上游 POST URL 限于配置目标的同一来源并加密绑定会话，平台认证头、Cookie、浏览器 Origin 不会转发给原 MCP 服务。

接入后可在「运行时防护 → 近 24 小时 MCP 工具活动」查看已保存拦截审计中的工具检查和阻断次数，并在下方实时流水核对工具名与策略。此处按工具名汇总检查事件，不按 MCP 端点区分；检查通过不等于上游执行成功，也不能作为账单或真实工具用量对账。

在「MCP 管理 → HTTP 接入配置」选择已保存的端点，页面下方的「此端点的工具用量」按工具名显示累计转发尝试、收到并通过检查的结果、失败、未知、进行中及平均耗时。管理员可点击「刷新用量」，或用带 `mcps:read` 权限的平台密钥读取 `GET /api/v1/mcp/endpoints/<端点 ID>/usage`；返回值仅含聚合计数，不含工具参数、结果或上游凭据。计数从本功能部署后开始，不回填历史调用。连接明确失败而请求未送达时不计为转发；上游拒绝、JSON-RPC 错误、工具 `result.isError: true` 和无效结果计为失败；断连或结果未确认计为未知，尚未结算的调用计为进行中，最长 15 分钟后转为未知。收到结果只说明代理收到了并检查了协议响应，不证明业务动作完成，也不是账单。

Agent/stdio 等远程 MCP 检查入口的工具用量在「运行时防护 → Agent / stdio MCP 代理工具用量」查看，也可用 `policies:read` 读取 `GET /api/v1/runtime/mcp/usage`。它按租户和工具累计经策略允许、取得配额租约的调用；调用方回报并通过检查的结果记为收到结果，JSON-RPC 错误、工具 `result.isError: true` 或已检查但被策略拒绝的结果记为失败，代理退出、上游未返回或结果未确认记为未知。重复结算不会重复计数，15 分钟后未结算的调用转为未知。这里只记录聚合计数，不保存工具参数或结果；允许转发不证明上游已执行。HTTP/SSE 端点的用量仍在各自端点页，两个口径不合并成账单。

stdio 客户端并发调用时，每个未完成请求要使用不同的 JSON-RPC `id`（数字或最多 128 字节的字符串）；平台代理按 `id` 对应租约，并在服务端核对未完成调用的返回结果 `id`。若上游返回了错误的 `id`，检查接口拒绝该结果，原调用仍占用配额直到正确结果、代理退出的未知结算或租约到期。排查时先核对上游是否原样回传请求 `id`，不要为释放配额而重发工具调用。

## 上游 OAuth 授权码接入

若企业授权服务的动态注册接口要求初始访问令牌，在 **动态注册（旧版兼容）** 表单的一次性输入框中填写。平台只将它作为当次注册请求的 Bearer 发送到授权服务发现文档声明的注册地址，不保存到客户端配置；再次填写令牌会强制重新注册。保存后清空该输入框，之后的授权码和刷新流程使用新注册客户端的凭据。

1. 先准备公开可访问的 **HTTPS 控制台入口**。控制台 **MCP 管理 → HTTP 接入配置 → 连接指南 → 上游 OAuth 授权** 的回调 URI 应为该入口加 `/mcp/oauth/callback`；Issuer、MCP 服务也须使用 HTTPS，仅本机回环测试可使用 HTTP。若上游授权服务声明 `client_id_metadata_document_supported: true`，优先选择 **托管 Client ID 元数据**，平台会生成公开 HTTPS 文档，授权服务可自行读取。若旧授权服务仅声明 `registration_endpoint`，选择 **动态注册（旧版兼容）**，由平台向该地址注册客户端；没有自动注册能力时选择 **预注册客户端**，先在上游登记完整回调 URI，取得 Client ID 和必要的 Secret。按上游文档填写 `offline_access` 等刷新令牌 scope。
2. 先清除端点中的固定 Bearer token。填写上游 Issuer、客户端注册方式及 scope；预注册方式还须填写 Client ID、认证方式和必要的 Secret。动态注册方式只选择客户端认证方式，平台保存时读取授权服务声明的注册地址、提交回调 URI，并加密保存返回的密钥；相同配置重复保存不会再次注册，修改 scope、Issuer 或回调等配置时会取得新客户端。托管方式保存后显示可复制的公开 Client ID 文档 URL，请确认上游授权服务能够从其网络访问该 HTTPS 地址。平台读取 MCP 资源的 `/.well-known/oauth-protected-resource/<资源路径>`，缺失时尝试来源根路径；两处均缺失时从上游 HEAD 的 401 Bearer 挑战读取同源 `resource_metadata`。平台核对 `resource` 同源、所选 Issuer 在授权服务清单里，并验证授权服务的 RFC 8414 或 OIDC 发现文档、授权码、S256 和所选客户端注册能力。没有可用发现文档时会明确报错，不猜测地址或把密钥发往重定向目标。
3. **先从已登记回调 URI 的 HTTPS 来源打开控制台**，再用管理员网页登录会话点击 **登录上游并授权**，在同一浏览器标签完成上游登录和同意。从局域网 HTTP 页面发起、再跳到另一个 HTTPS 来源会丢失当前标签页保存的授权绑定，因此页面会在发起前提醒切换入口。平台使用一次性状态与浏览器绑定、服务端 PKCE 验证器，以及授权响应 `iss` 的精确匹配；上游声明会返回 `iss` 时缺失也拒绝。完成后返回 MCP 管理，选择端点执行只读探测。授权码、访问令牌和刷新令牌不出现在端点列表或管理响应中；令牌密文绑定租户与端点。
4. 后续 HTTP 和 2024 SSE 代理会以 Bearer 访问令牌调用原服务。令牌临近过期时平台以同一资源标识自动刷新；没有刷新令牌或刷新失败时，管理员重新点击授权即可。修改 OAuth 配置或上游 URL 会使旧令牌失效，不会把旧凭据发送到新地址。**断开并清除令牌** 仅移除平台保存的令牌；若上游也需撤销，请在授权服务中撤销该客户端的授权。

OAuth 客户端配置由 `mcps:write` 管理，连接状态由 `mcps:read` 查看；平台客户端仍需独立 `mcps:execute` 和 `policies:read` 密钥。上游授权的 scope 与平台权限分别生效。托管 Client ID 文档只公开客户端名称、回调 URI 和协议能力，不公开租户密钥、scope 或令牌；配置修订或端点停用后旧文档 URL 失效。动态注册返回的 Client Secret 只加密存于服务端，到期时重新保存配置并授权；平台断开令牌不会删除上游注册的客户端，废弃客户端请在上游授权服务中撤销。当前可发现标准 well-known 资源元数据或同源 Bearer 挑战元数据；把 `resource_metadata` 指向不同来源的服务需要改为同源发现路径。

2026-07-28 连接关闭表示取消：平台关闭上游连接并归还并发配额。2025 协议的断连不证明原工具已停止，因此未完成调用的并发预留保守保留至租约到期（15 分钟）；收到最终响应时立即结算。客户端重试可能再次执行工具，平台不会自动重试。

2024 SSE 的工具 POST 只表示上游接收；最终结果经 GET 流返回。平台在收到并检查匹配请求 ID 的结果时结算配额；流断开而上游执行状态不明时保留预留，最长 15 分钟，不能把 202 Accepted 当成工具执行成功。若明确是上游 TCP 连接失败，请求没有送达，平台立即归还请求数与并发预留，会话仍可用于排障和重试；同一请求 ID 尚未完成时再次提交会返回 409，重复项不会转发或计费，客户端应等待原结果。上游返回拒绝状态时请求数计为一次、并发归还。2025/2026 HTTP 代理的明确连接失败也立即归还这些预留；上游明确返回非 2xx（含跳转）或完整的 200 正文时，请求数计为一次并立即释放并发。完整正文即使不合法也返回安全的 502，不把上游原文交给客户端；SSE 中已收到但格式错误或 ID 不匹配的帧记为失败并归还并发配额。发送后超时或连接中断无法证明工具未执行，仍保守等待结果或租约到期。重试前先核对上游执行记录。SSE 会话 60 秒空闲过期，活跃流每 15 秒刷新；探测结束会删除临时会话。

旧版会话标识替换为平台随机标识，绑定租户、调用者和端点版本；上游标识加密存储。会话空闲保留一小时，每个端点最多 1024 个会话，每租户最多 128 个端点。内网服务是管理员显式配置的出站目标；应通过部署网络策略限制可访问范围。

2025 Streamable HTTP 上游同时提供会话和 SSE 事件 ID 时，平台代理把上游事件 ID 加密封装为当前会话专用游标，无需逐条写数据库。网络中断后，兼容的客户端用**同一平台 Key、同一 `Mcp-Session-Id`** 发 `GET /api/v1/mcp/proxy/<端点 ID>`，在 `Last-Event-ID` 填最后收到的游标；平台代理验证游标后向上游恢复原流。空闲会话一小时过期，活跃流会续期；游标无效或会话过期须重新初始化。恢复能否拿到错过的事件取决于上游是否实现 2025 版重放，平台代理不会重新 POST 工具调用。没有上游会话或可用事件 ID 的流无法这样恢复。2026-07-28 协议没有 GET/`Last-Event-ID` 恢复，连接关闭表示取消；2024 双端点 SSE 断线后重新连接。

## 本地验收

`tests/support/mcp_http_server.cjs` 是不执行文件、系统或外部网络操作的回环测试服务，默认 `127.0.0.1:18084/mcp`，测试 token 为 `mcp-loopback-validation`，可用 `AGF_TEST_MCP_PORT` / `AGF_TEST_MCP_TOKEN` 覆盖。`readonly_echo` 支持 JSON/SSE，`redact: true` 返回固定虚构凭据用于验证脱敏。

运行 `cargo test -p agf-api --test mcp_http --test mcp_http_recovery --test mcp_http_lifecycle --test mcp_legacy_sse --test mcp_platform_key --test mcp_tool_usage --test mcp_tool_error_usage --test mcp_stdio_usage --test redteam_mcp_usage` 检查认证、来源、租户、会话、配置版本、事件游标隔离、原始凭据隔离、双端点 SSE、断连、配额、各入口工具用量和最小权限平台密钥接入。独立 PostgreSQL 双实例验收另需专属 `agf_requirements_test_*` 库和 `AGF_TEST_DATABASE_URL`，运行 `cargo test -p agf-api --test mcp_legacy_sse legacy_sse_session_and_post_uri_survive_a_second_api_instance -- --include-ignored`。真实业务服务连接需要业务方提供地址和授权，不包含在回环验收结果中。

## English quick start

For a private dynamic registration endpoint, enter its initial access token in the optional one-time field. The platform sends it as Bearer only to the advertised registration endpoint, never stores it in client configuration, and clears the field after saving. Entering a token again forces a new registration.

Open **MCP management → HTTP connections**. Select Streamable HTTP and enter its `/mcp` URL, or select 2024 HTTP+SSE and enter its `/sse` URL. Add the upstream bearer token, then test discovery. Follow **Create a platform API key** to Settings and select only `mcps:execute` and `policies:read`; the form does not preselect unrelated scopes. Export the client template, and connect to the generated `/mcp/proxy/<endpoint ID>` or `/mcp/legacy/<endpoint ID>/sse` URL through HTTPS or Compose host port 8092 (`AGF_MCP_PROXY_HOST_PORT`). The platform announces the separate SSE POST URL automatically. Upstream credentials are encrypted; clients receive a separate platform key. The proxy inspects requests and SSE/JSON responses and does not retry tools automatically.

For a 2025 Streamable HTTP server that issues both sessions and SSE event IDs, a compatible client can resume by sending GET with the same platform key, `Mcp-Session-Id`, and the last proxy-issued `Last-Event-ID`. The cursor encrypts the upstream event ID and is bound to that caller and session, without a database write per event. Idle sessions expire after one hour; active streams renew them. An invalid cursor requires a new initialization; missed events can only be recovered when the upstream implements replay. The 2026-07-28 transport has no GET or `Last-Event-ID` recovery. Never re-POST a tool call simply because the connection dropped.

When changing the upstream URL, re-enter its bearer token or explicitly clear the old token. An omitted field cannot carry the previous credential to a different destination.

After onboarding, open **Runtime protection → MCP tool activity (24h)** to review saved policy checks and blocks by tool name, then inspect the live interception stream. These counts do not prove upstream execution and are not billing or per-endpoint usage figures.

Under **MCP management → HTTP connections**, select an endpoint to see cumulative forwarded tool attempts and checked results by tool name. Refresh the table or call `GET /api/v1/mcp/endpoints/<endpoint ID>/usage` with `mcps:read`. A connection refusal before delivery is excluded; failed and unknown outcomes are separate. JSON-RPC errors and tool results with `result.isError: true` are failed. A malformed or mismatched SSE result is failed and releases concurrency; a disconnected stream without a confirmed result is unknown. Pending calls become unknown after 15 minutes without a confirmed result. Counts start when this feature is deployed and contain no tool payloads. A checked result is not proof of the business action or a bill.

For an Agent or local stdio proxy using the remote MCP check, open **Runtime protection → Agent / stdio MCP proxy tool usage** or call `GET /api/v1/runtime/mcp/usage` with `policies:read`. This tenant-wide table counts tool calls admitted by policy and a quota lease. Confirmed checked results, errors and unconfirmed outcomes are separate; JSON-RPC errors and `result.isError: true` are failed, and proxy exit is unconfirmed. It contains aggregate counts only and is separate from each HTTP/SSE endpoint's usage.

For concurrent stdio calls, use a distinct JSON-RPC `id` (a number or a string of at most 128 bytes) for each unfinished request. The proxy associates that ID with its quota lease, and the API rejects a mismatched result for a pending call without settling it. Check the upstream's ID echo before retrying; a missing result becomes unknown on proxy exit or lease expiry.

If read-only discovery is rejected, the console shows only the numeric JSON-RPC error code. Check the selected protocol, upstream permissions and server logs for details; upstream error messages and data are not displayed.

For an OAuth-protected upstream, use a publicly reachable HTTPS console origin. Prefer **Hosted Client ID metadata** when the authorization server advertises `client_id_metadata_document_supported: true`; the platform publishes a revision-bound public HTTPS document. Older servers advertising `registration_endpoint` can use **Dynamic registration (legacy)**: choose public or client-secret authentication and save; the platform registers the exact callback URI and encrypts any returned secret. If neither is available, register a dedicated authorization-code client with S256 PKCE and the exact `/mcp/oauth/callback` URI upstream, then select **Pre-registered client**. Save the MCP endpoint without a static bearer token, then open **HTTP connections → Connect → Upstream OAuth authorization**. Enter the issuer, registration method and scopes; manual Client ID and secret are needed only for pre-registration. Saving unchanged dynamic settings does not register again; changing them creates a new upstream client. Open the console from the registered HTTPS callback origin before clicking **Authorize upstream**, and finish in the same browser tab; starting on LAN HTTP cannot transfer this tab's authorization binding to another origin. The proxy encrypts access and refresh tokens, refreshes before expiry, and rejects tokens bound to a previous endpoint URL or OAuth configuration. Re-save and reauthorize when a dynamically issued client secret expires, and revoke unused registrations at the authorization server. Resource metadata may be at a standard well-known path or a same-origin `resource_metadata` Bearer challenge; off-origin challenge metadata is rejected.

For a protocol-level JSON-RPC error inside a successful HTTP/SSE response, clients receive the numeric code with a generic message. The upstream's raw message and data are withheld; inspect its own logs to diagnose the cause.

## 官方参考

- [MCP 2026-07-28 Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [MCP 2026-07-28 Client Registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)
- [MCP 2025-11-25 transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP 2024-11-05 HTTP+SSE transport](https://modelcontextprotocol.io/specification/2024-11-05/basic/transports)
- [Claude Code MCP configuration](https://code.claude.com/docs/en/mcp)
- [Cursor MCP integrations](https://prod.cursor.com/help/customization/mcp)
