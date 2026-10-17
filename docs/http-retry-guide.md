# API 重试与幂等键

浏览器正常操作不需要手工设置请求头。本指南适用于采集器、自研 Agent、CI 与企业平台集成。

## 正确使用

1. 每个独立写操作生成一个随机 `Idempotency-Key`（1–200 个可见 ASCII 字符，推荐 UUID）。不要把密码、API Key 或个人信息放入这个值。
2. 网络中断后，保留同一账号/服务身份、租户、HTTP 方法、完整 URL、请求内容和业务头，再用原键重试。请求正在处理时返回 409，先查询业务状态；已保存的成功 JSON 回执返回原状态和内容，并带 `Idempotency-Replayed: true`。
3. 改变请求内容应使用新的键。相同作用域下改变内容会返回 409；普通接口比较原始请求字节，JSON 属性顺序或空白变化也属于改变。`X-AGF-*` 数据分级/Agent 等业务头及客户端证书头参与检查。
4. 租户或实际资源 URL 不同就是另一项操作，不会返回其他对象的旧回执。认证凭据刷新后，只要身份与授权上下文仍一致即可复用；撤销、降权、MFA/改密要求、证书校验失败会被重新拒绝。角色、绑定 Agent、部门或来源地址变化时须核对原操作。
5. 服务器报错、连接中断、未知结果或不可缓存响应不能自动再执行。先查询任务、事件或资源实际状态，确认后再决定是否创建新操作。不要用不断更换键来绕过 409。

## 边界与排错

| 情况 | 含义与处理 |
|---|---|
| 400 | 键格式非法、请求体超限，或端点不支持通用幂等键。登录/认证/凭据签发端点拒绝此头；使用对应业务流程。 |
| 401 / 403 / 412 | 当前认证、权限、证书、MFA 或改密条件不满足。不能用缓存绕过。 |
| 409 | 参数改变、授权上下文变化、请求仍在执行或结果不确定。核对原业务记录。 |
| 429 | 速率或本地回执容量已满。稍后重试，保留原键。 |

普通回执是**单进程、有限时间内的重放保护**，不是分布式事务。上限为 2048 条、64 MiB 回执正文；成功 JSON 正文最多 2 MiB，输入缓冲最多 16 MiB，具体端点可更严格。在途请求不会因 TTL 被再次执行；结束后保留 15 分钟。服务重启、过期或请求被路由至另一实例时，普通回执不能保证去重，须结合业务对象 ID 和持久状态核对。

大响应、流式响应及带 Cookie 的响应原样返回，不会为缓存而截断；同键后续请求提示核对结果。MCP 代理不使用通用重放，不得把 JSON-RPC 请求 ID 当成副作用工具调用的去重许可。

红队提交有独立的**PostgreSQL 持久去重**：同租户同调用身份和相同规范化参数返回原任务，跨实例和重启保留固定用例版本。参阅 [红队指南](redteam-guide.md) 和 [定时巡航](scheduler-guide.md)。其他接口没有这项持久保证，不能据此推断所有写入均支持跨实例重试。

## English

Use one random `Idempotency-Key` per independent mutation. Retry a lost acknowledgement with the same caller, tenant, method, full URI, request bytes and application headers. Completed JSON receipts include `Idempotency-Replayed: true`. Changed inputs, in-flight work or uncertain outcomes return 409; inspect the business resource before issuing another operation. Every replay rechecks authentication and previously required permissions. Revoked credentials, changed roles, certificate failures and changed authorization context cannot reuse old write results.

Generic receipts are local to one process: up to 2048 entries and 64 MiB, 2 MiB per successful JSON response, retained for 15 minutes after execution ends. Active work cannot expire into a second execution. Restart, expiry and another replica are outside this guarantee. Large or streaming responses remain intact but are not cached. Authentication and credential endpoints reject this header; MCP proxies use their protocol semantics. Campaign submission has its own durable PostgreSQL contract. Always distinguish a replay receipt from a durable business transaction.
