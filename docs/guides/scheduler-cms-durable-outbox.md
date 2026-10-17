# Scheduler CMS 持久队列

`alicloud-cms-push` 将本周期每个指标的原始 payload 和固定时间先保存到
`<AGF_REPORT_DIR>/cms-outbox/<tenant>/<run>/payload.json`，再通过平台服务身份调用
`/api/v1/alicloud/cms/queue`。同一租户和周期执行编号派生固定 run/enqueue/send UUID；
重启或重试读取原文件，统计值变化不改变原 intent。文件不包含平台 Key、JWT 或云 AK。

队列以控制台当前 CMS 源为准，需要 `alicloud:read/write` 服务权限。
无身份、无启用源或平台离线时，全部 payload 留在本地；任务明确报告降级或失败，
不会声称已入平台队列、已获 Mock 接受或已触达云端。后续周期会尝试处理保留的记录。

显式配置的 Mock 源通过同一持久队列发送，回执标注 Mock 和
`providerWriteAttempted=false`。仅 `cn-hangzhou/agf-cms-demo` 会初始化其专用 Mock fixture。
Live 默认只入队；运维另行设置 `AGF_SCHEDULER_CMS_CONFIRM_LIVE=true` 才能提交一次 send。
本轮验证只使用 Mock 和本机 loopback；Live 入队测试的配置密钥均为合成字符串，不发送云请求。

`enqueue.json` 和 `send.json` 保存不可变 API 输入；提交 send 前持久保存
`send-started.json`。若 send 回复丢失，恢复只查询原 UUID。即使原回执暂时为 404，
也不会再次 POST send。Accepted、Unknown、执行中或待审计结算都不创建新发送 intent。
`recover-local` 仅结算已有尝试和审计，不会调用云端。任务按原尝试的完成状态及逐项
delivery 报告接受数量；不把本地入队或 provider 接受推断为 consumer 已应用。

配置版本、generation、所有者或平台 origin 变化时原 wire 不改写；保留记录并报告阻塞。
确认 NotSent/Rejected 后，运维可使用原服务身份在 CMS 队列中明确提交新尝试；
Unknown 必须先查清，不能把新 UUID 当作重试。平台队列的容量与永久身份约束保持不变，
达到容量需审查并显式归档已完成记录；本任务不自动删除 payload、审计或永久身份。

outbox 复用现有制品路径校验，拒绝 symlink/reparse 和跨租户封套；每个阶段校验 SHA-256。
租户级操作系统文件锁在进程退出时释放，防止并发执行写入同一批文件。
阶段写入先 `sync_all` 完整 `.pending` 文件再 rename；重启校验后恢复完整 pending。
截断或哈希错误文件保留并阻止调用，禁止猜测或覆盖。单文件 64 KiB、总计 16 MiB、
最多 1024 周期；每轮最多处理当前周期加 16 个历史记录，HTTP 与整轮时间均有上限。
达到预算时停止新增 intent，保留全部已有证据，需运维审查归档后继续。
