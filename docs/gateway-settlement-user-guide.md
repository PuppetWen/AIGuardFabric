# Model settlement recovery — integration candidate

This guide describes an unregistered candidate. Definitions and static checks do not establish deployment, cloud-provider validation, or full WP7 completion.

Durable authenticated calls reserve quota before dispatch. An original request freezes at most eight ordered chat candidates and sums their worst allowed consumption before any model POST. Explicit fallback preserves its configured order; each physical candidate enters at most once. Streaming uses the same reservation and settlement. Internal/offline calls retain their established lane and are not claimed atomic. Authenticated external calls backed by SQL refuse unsupported complete-source capacity or more than eight eligible candidates before any model request; they never fall back to weaker accounting. Selecting a fallback never resets the original 110-second execution deadline.

A server-created `x-agf-attempt-id` is returned after admission on successful and failed HTTP responses, including SSE response headers. Authenticated fixed permission/policy/quota refusals also return their committed Failure fact UUID; unauthenticated or uncommitted preparation errors have none. Preserve the header before recovery. For supported OpenAI aliases, supply your own `Idempotency-Key` before the first call: original input bytes and business headers are bound to a permanent actor-local namespace. A duplicate reservation is 409 and dispatches nothing. If its response was fully lost, `GET /api/v1/gateway/attempts/by-idempotency-key` with that same header and current original subject can read the original safe receipt. A 404, pre-reservation refusal or unsupported legacy lane never proves no paid request occurred; do not resend to discover an ID.

For a supported single-candidate nonstream call, an enabled live semantic profile reserves the configured embedding token ceiling and chat estimate together before the first paid POST. The profile uses the real original OpenAI wire body and current Agent/policy/source evidence. Embedding has a distinct stable Usage UUID; a semantic hit makes chat fee zero while preserving paid embedding fee, logical chat tokens and one logical Request. Embedding over-reservation charges actual usage without clamping and forbids a later chat POST. Streaming and fallback bypass semantic lookup and never start a paid embedding implicitly.

The receipt's top-level `usageId` and `outcomeEvidence` refer to the primary chat candidate. `components` contains only additional reserved candidates and embedding, at most eight entries. `not-sent` consumes nothing; `sent-usage-known` has complete trusted numeric usage; `sent-usage-partial` preserves only the observed numeric lower bound; `sent-usage-unknown` has no trusted usage row. Partial or unknown sent candidates are charged conservatively, at least their own original estimate and any larger observed lower bound. These estimates do not prove the external provider's final invoice. A failed first candidate and a successful paid fallback are both accounted under one logical Request, with distinct stable Usage UUIDs.

SSE content can arrive before the final transaction, but an intentional finish marker and protocol terminator are withheld until usage, both ledgers, checkpoint and real audit commit together and current delivery authority passes. An explicit private commit proof is required for OpenAI [DONE] or the Anthropic terminator. A confirmed safe ContentFilter replacement can end normally after its Failure audit commits; protocol completion is not a Success audit. Provider usage/finish fields and closing the worker channel are not that proof. Missing complete evidence, unexpected failure, cancellation or unexpected owner closure produces an explicit stream error, never a fabricated success. Disconnect cancels later polling and candidate dispatch; already received numeric usage remains staged. It does not prove a remote request already sent was cancelled. Complete, partial and unknown outcomes survive local audit failure and can be published locally without a new provider connection.

Read `GET /api/v1/gateway/attempts/{id}` explicitly. It is entirely local and does not initialize, maintain, write an audit, recover, call a model or grant execution. Its safe receipt does not expose prompts, responses, credentials or encrypted bodies. `components` distinguishes the separate paid evidence.

`pending-audit` means authenticated known evidence exists but final usage, both quota ledgers, optional semantic-cache insertion, durable Meter checkpoint and tenant audit have not committed together. The same original subject with current identity and `models:write` may send `{}` to `POST /api/v1/gateway/attempts/{id}/recover`. Recovery is local publication and never repeats a provider call. Repeating committed recovery does not add usage, charges, a checkpoint revision or terminal audit. Another actor, including an administrator, cannot substitute for the original subject.

Use the same tenant through `X-AGF-Tenant`. GET requires current `models:read`; recovery requires current `models:write`. For a User-origin call, the same User's current authenticated console session may operate the manual panel. For an API-Key-origin call, use the original API Key from your own HTTP client, for example an `Authorization: Bearer ...` header. The console does not accept or store that raw Key and its User identity cannot recover the Key's attempt. No typed SDK recovery helper is claimed. Expired or revoked identities have no recovery or renewed dispatch grant.

`reserved` grants no retry permission: every receipt has `mayExecute:false`. After expiry, fixed internal service maintenance may release original concurrency and charge original estimates in the original quota bucket with a real system audit. `conservatively-settled` is accounting uncertainty, not model success. Later known evidence may correct the original charge snapshot without refunding another window.

`settled` means local accounting and the real audit committed. It can accompany an actual Failure audit for output refusal, revoked authority, timeouts or unknown consumed usage. An audit UUID identifies an audit entry, not a successful model result. Consult actual evidence and Failure/Success outcome; do not treat terminal Failure IDs as success.

Optional cache-only source changes can omit the cache insert with an explicit audit disposition; they cannot grant dispatch or response delivery after main authorization/Agent changes. Real storage errors keep the known outcome pending. Cached response TTL is never renewed by recovery. Durable checkpoints preserve exact tenant totals and monotonic revisions; bounded display groups may merge into an explicit other group. Memory projection refusal is explicitly marked incomplete while durable ledger/Usage evidence remains authoritative.

This candidate still needs actual compilation/SQL validation and the manual panel's matching partial-evidence/eight-component contract before deployment. Remaining scope includes uniform auditing of every malformed/pre-auth/unsupported legacy denial, legacy interception UI projection, exact remote invoices for unknown usage, full vendor streaming protocol coverage and permanent evidence retention policy. Fixed service maintenance only cleans original reservations; it does not replace the original actor for known-result recovery. The default-off literal127 test capability is absent from normal release builds and does not authenticate arbitrary HTTP URLs.

---

# 模型结算恢复（集成候选）

这是独立候选能力。源码定义与静态检查不代表上线、真实云验收或 WP7 全部完成。持久化且已认证的原请求固定最多八个有序 chat 候选，组合保留所有允许候选的最坏消费，流式与非流式共同结算；显式回退遵循原配置，每个实际端点最多进入一次。回退不重置原 110 秒期限。内部/离线调用保留既有 lane，不能声称其已原子结算。已认证且由 SQL 支撑的外部请求，来源完整集合超容量或可用候选超过八个时，在模型发送前明确拒绝，不回落弱计量路径。

成功、失败及 SSE 响应头保留服务器生成的 `x-agf-attempt-id`；固定的已认证权限/策略/配额拒绝在 Failure 事实提交后也有 UUID，未认证或未提交的准备错误没有。支持的 OpenAI 入口可在首次调用前填写自己的 `Idempotency-Key`，永久绑定原主体、原输入字节及业务请求头；重复领取返回 409，零派发。完全丢失响应时，可用原 Header 明确 GET `/api/v1/gateway/attempts/by-idempotency-key` 读取原事实。404、领取前拒绝和旧 lane 不证明没有远程消费，不要为找 ID 而重发。

只有支持的单候选非流式调用采用显式语义 profile、真实原 OpenAI wire 及当前 Agent/策略来源；embedding 与 chat 组合预留，各有稳定用量 UUID。语义命中保留 embedding 实际费用及 chat 逻辑 token；embedding 超预留不截断实际费并禁止后续 chat。流式/回退跳过语义查询，不隐式付费 embedding。回执顶层指主 chat，components 只列额外候选/embedding，最多八项。not-sent 不收费；known 是完整可信数值；partial 仅证明已观测下界，unknown 没有可信用量行。partial/unknown 的账本按原估计与更大下界保守收费，不能说已证明云厂商最终账单；失败首候选和付费成功回退都计入同一逻辑 Request。

SSE 正文可能先交付，但有意的结束标记/协议终止须等待真实用量、双账本、checkpoint 和审计同事务提交，并再次通过当前交付权限。OpenAI [DONE] 与 Anthropic 终止须有工作任务发出的私有提交证明；已确认的安全 ContentFilter 替代，在对应 Failure 审计提交后仍可正常结束，协议完成不等于 Success 审计。provider 的用量/finish 字段或通道关闭都不是证明。证据缺失、意外错误、取消或工作任务意外关闭时返回固定流错误，不伪造 Done。客户端断连停止后续轮询/派发，已收到数值保留；不证明远程任务已取消。审计故障保留完整/partial/unknown 安全证据，恢复不重新连接模型。

显式 GET 原回执是纯本地读取，不初始化、不维护、不审计、不恢复、不调模型；安全 DTO 不包含输入、回复、密钥或密文正文，components 保留独立组件证据。pending-audit 表示真实用量、双配额账本、可选语义缓存、持久计量 checkpoint 和审计尚未共同提交。原主体当前身份有效且有 models:write 时，可明确 POST 空对象 {} 纯本地恢复；重复恢复已提交事实不会增加收费、用量、checkpoint 代次或终态审计，也不会重派模型。

请求须保持同一 X-AGF-Tenant；读取需要 models:read，恢复需要 models:write。User 发起的事实可由同一 User 当前控制台会话操作。API Key 发起的事实必须由原 Key 的自有 HTTP 客户端提交，例如 Authorization: Bearer 请求头；控制台不收集或存储该原始 Key，控制台 User 不能代替它恢复。未声称 SDK 已有类型化恢复方法。过期、撤销或不同主体没有恢复或新执行许可。

reserved/所有 GET 的 mayExecute:false 均不是重试许可。固定服务维护仅能在过期后释放原并发、按原账桶保守计费并写真实系统审计；不获得新的业务权限。conservatively-settled 不证明成功，迟到实际用量只能更正原快照，不能返还别的窗口额度。settled 证明本地结算与真实审计提交，仍可能是输出拒绝、撤权或未知消费对应的 Failure。审计 UUID 不是成功标识，必须核对实际审计结果。

仅缓存来源变化可明确省略缓存插入，不能让已变更的主调用权限或 Agent 分级重新获得外发/交付许可。真实存储错误保留 pending，恢复不延长原缓存 TTL。持久 checkpoint 保持精确租户总额和单调代次，细分显示组可并入显式 other；内存投影拒绝会明确标记不完整，持久账本仍是权威。

本候选仍待实际编译/SQL，以及手动面板匹配 partial/八附加项合同后才可部署。全部无效/未认证/旧 lane 拒绝统一审计、旧拦截 UI 投影、未知消费精确云账单、全部厂商流协议和永久事实容量仍有边界。固定服务维护仅清原预留，不代替原主体恢复已知结果。默认关闭的 literal127 测试 feature 不存在于普通发行构建，不授予任意 HTTP 地址权限。


## Protected admission limits / 受保护准入限制

The complete nine-kind configuration witness has at most 512 records and 8 MiB of encoded JSON in total; singleton kinds must actually be singletons. Session must contain 1–256 UTF-8 bytes and the model selector at most 256; the existing auto selector remains valid. The evaluated chain must contain 1–8 eligible chat endpoints. Capacity refusals are 412; invalid session/model or candidate-count limits are 400. When current original authority permits its Failure transaction to commit, the response retains x-agf-attempt-id, a not-sent safe receipt and no new usage or charge. Audit/storage failure does not fabricate that receipt. Reduce the configuration/request bounds, inspect the original receipt, and issue a new explicit call only when appropriate; neither GET nor local recovery starts a model.

完整九类配置见证最多 512 条、实际编码 JSON 合计最多 8 MiB，单例配置必须真实唯一。session 为非空 1–256 UTF-8 字节，model 选择器最多 256 字节，保留原 auto 自动选路。实际可用 chat 链为 1–8 个端点。来源容量返回 412，请求字段或候选数量限制返回 400。只有当前原权限允许 Failure 事务提交时，响应才携带原 x-agf-attempt-id 与 not-sent 安全回执；该拒绝不产生新用量/收费。审计或存储故障不会伪造已提交回执。调整配置/请求前先检查原回执，确需新调用时显式操作；GET 和本地恢复均不发送模型。
