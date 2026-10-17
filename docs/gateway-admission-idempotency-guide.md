# Recover an admitted model request by its caller key

This candidate adds durable admission keys to the PostgreSQL-backed, authenticated,
nonstream, single-endpoint gateway lane. It has not been compiled, deployed or
verified against a provider. Ordinary stream, internal, fallback, no-key and
memory-only calls keep their existing behavior and do not acquire this guarantee.

Before sending a supported request, create and retain one `Idempotency-Key` of
1–200 printable ASCII bytes. Retain the exact request bytes, business headers
and chosen URL. Send it to either `/v1/chat/completions` or
`/api/v1/chat/completions`. A first admission needs the current `models:write`
permission. The index, original attempt, two quota reservations and admission
audit commit in the same transaction before a model or embedding request starts.

An occupied key cannot create another attempt. A duplicate returns 409 and,
after current original-owner `models:read` plus `models:write` authorization,
the `x-agf-attempt-id` of its original attempt. It does not fabricate a successful
model response or dispatch another request. Changing the input, concrete alias,
query or business headers also returns 409. Changing the bound Agent cannot
split the namespace into a fresh attempt. A write-only Key can make the initial
request, but receives no original ID when it later lacks read permission.

If the initial response is completely lost, use a pure local GET with the same
header and current original credentials:

```http
GET /api/v1/gateway/attempts/by-idempotency-key
Authorization: Bearer <original credential>
Idempotency-Key: <original caller key>
```

Do not put the key in a URL, application log or support screenshot. The lookup
accepts no query parameters. It requires current `models:read`, the original
tenant, subject kind, subject and bound Agent. The original User may sign in
again with a valid new session. Another administrator or User cannot act as the
original Key. Lookup reads the real safe settlement receipt and never contacts
the provider, refreshes STS, initializes configuration, charges quota or appends
an audit. Every receipt has `mayExecute: false`.

404 means that this actor/key has no durable index. It can also describe a legacy,
stream or fallback request, and is not proof that a provider received nothing.
Do not automatically retry a model call after 404, a timeout or an uncertain
receipt. A retired/corrupt index fails closed and cannot be silently recreated.

If the receipt exposes authenticated known evidence awaiting audit, the same
original actor can explicitly POST `{}` to
`/api/v1/gateway/attempts/{attemptId}/recover`. This publishes existing evidence
locally under the current `models:write` grant. It does not send a model or
embedding request. A Key-origin request must be read and recovered with that
Key; a console User cannot substitute for it. Unknown consumption remains
conservative, and independently paid embedding usage remains chargeable.

Permanent admission keys have a lifetime capacity of 16,384 per tenant. A full
capacity rejects a new admission with 429 before dispatch. There is no automatic
expiry, eviction or reuse of an occupied key. Source deletion or retargeting does
not authorize another model request under an already occupied key.

The keyed request carries one server-created 110-second window from middleware
entry through lookup, preparation, source/authority waits and admission. It does
not extend that execution window after a slow lookup. Known completion and
explicit local recovery retain the existing settlement rules. Cancellation can
lose a client response while the already admitted owned completion records its
outcome; it must not be interpreted as permission to issue another model call.

The index stores an authenticated encrypted original owner and HMAC identities,
not a raw caller key, prompt or full response. Encryption/HMAC master-key rotation
requires a migration that preserves permanent occupied namespaces. Replacing
the key without migrating indexes is not a supported reset/retry mechanism.

## 中文操作说明

此候选仅针对已认证、PostgreSQL 持久化、非流式且单端点的准入链路。
每次新请求先生成并保留一个 `Idempotency-Key`，连同原请求字节、业务 Header
和 URL 保存。首发需要当前 `models:write`。两条聊天 URL 共用同一主体与 Key
命名空间；换 URL、换正文或换绑定 Agent 都不能自动领取新的模型执行。

已领取的 Key 返回 409。只有原主体仍具备 `models:read` 和 `models:write`
时才披露原 `x-agf-attempt-id`，不会伪造成功响应，也不会重新调用模型。
首响应完全丢失时，使用原凭据和原 Header 对上述固定 GET 入口查询。
Key 不进入 URL、日志或截图；查询不联网、不写配置、不追加审计、不授执行许可。

404 不能证明厂商没有收到请求，也不能触发自动重发。原主体可对已知待审计
证据显式调用原编号的 `/recover`，仅做本地结算恢复。管理员不能代替原 Key。
持久 Key 每租户最多 16,384 个，满额时首发在模型调用前返回 429；无自动淘汰。
流式、fallback、内部调用和无数据库模式仍保持原行为，不宣称具备此持久保证。
