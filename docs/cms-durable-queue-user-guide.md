# CMS 持久补传队列 / CMS durable delivery queue

候选实现，尚未部署或执行验收。入口是阿里云页面的 **CMS 持久补传队列** tab（`/alicloud?tab=cms-queue`）。只有从该入口或对应 typed API 明确提交的事件、指标进入队列；通用 CMS 操作和 Scheduler 环境指标直接上报不自动进入队列。进程内 `OfflineQueue` 不构成重启可恢复的证据。

This candidate has not been deployed or accepted. Open **AliCloud → CMS durable delivery queue**. Only explicit submissions through this page or its typed API enter the queue. Generic CMS operations and Scheduler direct metric reporting remain direct calls. The process-local `OfflineQueue` does not prove recovery after restart.

## 配置与 Mock 演示 / Configuration and Mock demonstration

1. 在页面上方保存启用的 CMS 连接，填写已有 GroupId。Mock 演示固定使用 `cn-hangzhou` 和 `agf-cms-demo`；真实发送要求正数、规范十进制 int64 GroupId。现有凭据在连接设置中配置，队列表单不接收 URL、Key 或原始 action。
2. 选择事件或指标。事件填名称和正文；指标填有限数字和最多16组非空字符串维度 JSON。名称按 UTF-8 最多128字节，正文最多4096字节，每条实际 JSON 最多16KiB。
3. 首次 Mock 入队时明确勾选初始化演示种子。GET 永不创建种子；已有种子不覆盖。**明确入队**只保存加密正文和本地意图，不表示 CMS 接受。
4. 选中条目，点击 **新明确补传意图**。Mock 不联网，接受记录和本地 Execute 审计同事务；持久数据库模式下第二实例可读取原记录。无数据库时仅同进程可恢复，不能声称跨重启持久。

Save an enabled CMS connection above the tab. The Mock fixture has the exact region/group tuple listed above. Live needs a canonical positive int64 GroupId and existing connection credentials. Fill an event name/content or a finite metric value with at most16 nonempty string dimensions. Explicitly initialize the Mock fixture on its first enqueue; GET never seeds and existing seeds are never overwritten. Enqueue retains encrypted content and local intent only. Select the item and manually send. Mock acceptance and its terminal audit commit atomically, without cloud traffic; memory offline mode is process-local.

## 发送事实与未知 / Delivery evidence and Unknown

- 每次新 Send UUID 是一个新的明确补传意图，持有从服务端捕获起算的原110秒预算，涵盖授权、队列、SQL/审计锁、STS和唯一 provider POST；同 UUID 不能续期、重新领取或重派。
- 每条至多5次明确发送意图。只有 `not_sent`（明确未发送）或 `rejected`（可信拒绝）终态可发起新意图。5次耗尽后是死信；不会自动清除永久身份或再次发送。
- `accepted` 是严格的 CMS API 控制面 ACK，不表示消费者处理。ACK 只接受 HTTP200、字符串 Code="200"、安全 RequestId，部分/未知响应不算成功。消费者状态始终 unknown。
- CMS 的这两个 API 没有幂等 ClientToken，不能保证外部效果恰好一次。已进入 transport 后的超时、断线、5xx、缺少或矛盾 ACK 等为 `unknown`，绝不自动重试，也不因后续数据匹配升级成 accepted。
- `pending_audit` 保留已发生的安全结果，但本地终态审计尚未发布；界面不能显示为完整成功。已保留 Accepted 的失败审计不使其再次获得发送许可。
- 源配置、凭据或版本变化阻断旧条目新发送。不会给旧请求换新来源或刷新其权限。源停用后仍可读原事实、以当前原主体授权做本地结算或归档终态正文。

A new Send UUID is a new explicit intent with one original110-second budget. A replay of the old UUID never obtains a new dispatch permission. At most five explicit intents are allowed per item, and only completed `not_sent` or trusted `rejected` outcomes may be retried. Accepted is a strict CMS API acknowledgement, not consumer processing. The APIs have no idempotency ClientToken. Once transport starts, unconfirmed responses remain Unknown without automatic retry or later promotion. Pending audit retains evidence without claiming local terminal success. Source revisions never replace the original source of an old intent.

## 原 UUID 恢复与归档 / Original UUID recovery and archive

写入前页面把原请求 UUID 保留在 `cms_queue_request_id`。响应丢失后保持草稿，点击 **读取原回执**，或使用 GET `/api/v1/alicloud/cms/queue/requests/{UUID}`。404 不证明未发送，不解锁未知写入，也不自动换编号。可信原回执或明确4xx拒绝后，仍须人工点击允许新操作；它不重新发送旧请求。

**仅本地结算**调用 POST `/items/{id}/recover-local`，正文必须 `{}`。已有 retained result 按其原事实提交唯一 Execute 终态审计；没有结果时须等原租约过期，未 started 的请求记 `not_sent`，started 的请求永久记 `unknown`。该路径不联系 CMS、不做 STS、不续发、不重新初始化 Mock。完成后的重复恢复纯读取。

控制台只可恢复同登录 User 的请求。Key 发起的请求必须使用原 Key 和同 Agent 绑定，且当前仍有 `alicloud:read` / `alicloud:write`；管理员 User 不能替代。读取回执只需当前原主体的 read 权限。原JWT到期、当前角色/Key撤权在等待之后也会拒绝提交。

归档每批最多32个终态或尚无发送的条目，仅释放正文；原 ITEM、ATTEMPT、REQUEST UUID 和结果永久保留。活跃/未结算条目不能归档。归档不会让 Accepted/Unknown 变成可重发。相同归档 UUID 的同正文重读不写审计；新的归档 UUID 即使 changedCount=0，也实际创建本地请求事实和 Create 审计，并推进代次，不能冒称无写操作。

Before a write, the page retains the original UUID in its URL. Read that UUID after a lost response;404 does not prove that nothing was sent. Local settlement accepts only `{}`, retains the original outcome and never contacts CMS. An expired admitted attempt becomes NotSent; an expired started attempt without evidence becomes permanent Unknown. The same original User or Key is required, with current grants and the original JWT checked after waits. Archive removes payload content, not permanent identities or outcomes. A new archive UUID is a real audited local configuration write even when it changes zero items.

## 容量、API与验收边界 / Limits, API and acceptance boundaries

队列最多128个详细条目、2MiB正文和4096个永久事实；满额拒绝，不自动逐出 UUID。单次入队/发送最多20条，发送逐条唯一 POST，停止/取消后不启动后续条目。Mock 接受记录另限512条。AEAD绑定 tenant、kind、record ID；SQL使用同 source → queue state → 排序 related → audit 锁，审计后复查原主体、租约和预算。归档32条最多98个声明键（含 STATE、归档 REQUEST 和每项 ITEM/BODY/最新 ATTEMPT），保持≤100 related/1MiB单记录/8MiB完整批预算。

API：GET queue / items/{id} / requests/{id}；POST enqueue / send / items/{id}/recover-local / archive。请求为严格 snake_case，响应为安全 camelCase；未知字段和不支持分页400，同 UUID不同正文/用途409，来源/CAS冲突409，不可发送/容量/持久前提缺失412。所有 GET 不发送、不修复、不初始化、不写业务审计。

Stage-one tests are defined using the actual router, encrypted Mock state, tenant-owned loopback CMS transport with independent ACS3 MAC validation, and exact-owned PostgreSQL cases. They have not been executed in this candidate. No real vendor credentials or stage-two cloud acceptance is claimed. Mock availability does not prove CMS cloud semantics.

官方协议依据 / Primary protocol references:

- [PutCustomEvent 2019-01-01](https://www.alibabacloud.com/help/fr/cms/cloudmonitor-1-0/developer-reference/api-cms-2019-01-01-putcustomevent)：EventInfo、Unix毫秒 Time、Code/RequestId；每条独立发送以避开部分批次的未知结果。
- [PutCustomMetric 2019-01-01](https://www.alibabacloud.com/help/zh/cms/cloudmonitor-1-0/developer-reference/api-cms-2019-01-01-putcustommetric)：MetricList、Type、字符串 Values/Dimensions、Code/RequestId；不虚构 ClientToken 或服务器幂等能力。
