# AgentTeams Trace 观测查询

## 接入自己的业务

1. 在「阿里云 → 云连接」配置 AgentTeams，完成团队、Worker 与资产关系盘点。
2. 在「日志接入」建立并启用 APIWebhook 源，在「阿里云 → 消息与调用审计」绑定当前实例。
3. 在「设置 → API Key」建立只有 `sources:write` 的采集 Key。该权限属于租户，并非日志源专用。
4. 选择服务端显式采集器：[Python SDK](../sdk/agentteams/python/README.md) 或 [Node SDK](../sdk/agentteams/node/README.md)。
   Python 使用标准库 SQLite；Node 要求 ≥24 且内置 `node:sqlite` 可用，已验收目标机 24.18.0。
   采集器放在自己的应用进程中，不能把采集 Key 放入浏览器。
   不改业务文件时，可选择 [Python 启动注入](agentteams-sdk-injection-user-guide.md) 或
   [Node CommonJS 启动注入](agentteams-node-startup-guide.md)。它们仅覆盖明确配置的真实调用边界；
   Node 通用 ESM、worker threads、class 和已预加载导出仍需显式接入，不能当作完整调用图。
5. 配置真实平台地址、sourceId、bindingId、scopeId 和 Mock 标识，为每个进程和绑定建立独立磁盘队列。
   先运行 SDK 的 heartbeat 示例检查接收，再显式包装真实 Worker 的 Task、跨 Worker 调用和消息发送。
   心跳只证明本次遥测接收，不产生虚构的任务、调用、耗时或成功状态。
6. 同进程上下文使用 SDK 的上下文管理；跨进程由自己的业务协议携带 SDK 标识载体。
   接收方显式读取载体。缺少、无效或不匹配载体时形成独立根，不按团队名或时间猜测父关系。

模型网关 Key 与采集 Key 分开。业务网关 Key 使用 `models:write` 并绑定实际 Worker 资产，
采集 Key 只发送遥测，不替代模型授权、配额绑定或业务请求凭据。
SDK 默认不采集参数、返回值、异常文本和原始消息；包装保留业务返回值、异常、取消和流行为。
业务函数只执行一次。接收响应丢失时重传相同事件 ID，不重新执行任务或业务调用。
重新绑定或更换账号后隔离旧队列，不能把旧事件改绑后重发。
具体磁盘上限、队列满时行为、HTTP 重定向拒绝与恢复方式请按各 SDK README 操作。

## 人工查询

查看需要同时具有 `alicloud:read` 与 `sources:read`，不需要云写权限。
打开 `/alicloud?tab=audit`，在真实事件的 Trace / Span 列点击「选择 Trace 查询」。
这一步只预填 Trace ID 和实际审计记录 UUID，不自动发起查询。
也可直接在「Trace 观测查询」填写实际标识。允许 1–128 位字母、数字、下划线、点、冒号和连字符。

起止时间都按 **UTC** 解释；结束时刻不包含在窗口内。窗口必须为正且不超过 30 天，
结束时间不能超过当前时间 60 秒。控件省略零秒时按 `:00` 处理。
默认窗口为最近 24 小时；点击「查询 Trace」才发起只读 GET。
每页事件为 20、50、100 或 200 条。事件页与关系节点页分别分页。

接口为 `GET /api/v1/alicloud/agentteams/traces/{trace_id}`，使用 RFC3339 `from`、`until`，
可选 `limit` 与服务端返回的不透明 `cursor`。不要拆解、拼接或修改游标。
该查询不会写云、恢复云操作或重放业务任务。

## 读懂证据

- 「窗口事件数」是同一次数据库查询快照的完整计数；关系视图最多返回该快照中的 2000 个节点。
  超过上限会明确标记截断，缩小时间范围后再查询。
- 节点是实际平台审计记录 UUID，Event ID 是发送端稳定事件身份；二者不能互换。
- 点击记录 UUID 查看其真实 Span、父 Span、参与方和邻接边。
  只有已报告且可消歧的 `parent_span_id` 形成边，不依据 Task、Team、Worker 或时间推测边。
- 每屏显示最多 50 个节点和 50 条所选节点邻接边。页面分别列出本屏可见、筛选与后端已返回数量。
  局部列表不是完整树，未显示的节点也不表示不存在。
- 缺少 Span、缺少父记录、重复 Span、父 Span 不唯一、循环或父记录冲突保留为未知或冲突。
  同一 Span 的多条记录不会被合并成一个已证实节点。
- 盘点不可用时数量为未知，不能显示成 0。有效范围下数量 0 只表示本窗口未观测到该 Trace。
  所有图都标记 `complete=false`、仅观测覆盖；缺日志、截断和时钟偏差都可能留下缺口。
- Mock、日志、正常返回和 Trace 都不能证明调用已授权。授权结论保持未知，不算作已授权或未授权。

## 翻页失败与刷新

游标有效期为 30 分钟，绑定于租户、云范围、Trace、时间窗和接收水位。
相同内容的日常盘点刷新不影响游标；更换云配置或范围、旧快照记录迟提交、删除或改变可能返回 409。
查询水位之后收到的新记录不混入已有事件页，点击刷新后建立新快照再查看。
同一云范围的历史来源绑定记录仍可作为观测证据，不表示旧绑定可继续发送。

遇到 409 时保留原结果并停止翻页，点击「刷新 Trace 查询」从原时间窗第一页重新建立快照。
400 可能是无效、过期、被修改或与查询不匹配的游标；核对 Trace、时间窗和权限后人工刷新。
刷新不会把新旧事件页拼在一起。修改 Trace、时间或每页数量会清除旧查询；需重新点击查询。
从第二页返回第一页只恢复同一查询保存的第一页与原接收水位，不发新 GET；返回其他页继续核对原游标快照。
要查看新接收的日志或重建快照，必须显式点击刷新；返回第一页不能绕过快照冲突。
切换租户、登录会话或失去任一查看权限时旧结果立即隐藏，过期请求不会覆盖新页面。

平台只对已收到的显式遥测提供证据。查询结果不表示云厂商完整任务历史、业务执行成功、真实权限通过，
也不提供未公开的厂商任务重放 API。

For unchanged application files, use the [Python startup guide](agentteams-sdk-injection-user-guide.md)
or the [Node CJS preload guide](agentteams-node-startup-guide.md). Unsupported or unobserved
call boundaries remain gaps; receipt acceptance never proves business authorization or cloud replay.
