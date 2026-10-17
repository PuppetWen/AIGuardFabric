# 自动告警升级 / Automatic alert escalation

## 中文操作指南

1. 打开“系统设置 → 通知设置”。配置并启用通知渠道，先发送测试通知，检查投递记录。个人用户可使用站内消息；企业可接入钉钉、飞书、企微、SMTP、短信、Webhook、PagerDuty、Slack。模拟模式的外部回执会明确标注演练，不能作为真实平台送达证明。
2. 打开“告警中心 → 升级路由配置”。五个严重等级分别设置响应目标，每级最多三个升级层级。默认全部停用。响应目标 15 分钟、L1 超时 5 分钟，表示告警首次发现 20 分钟后触发。逾期分钟必须严格递增。
3. 每级选择已配置、启用且最低严重等级兼容的渠道。接收地址来自通知设置；角色标签只描述升级对象，不自动指派用户，也不覆盖渠道收件人。
4. 填写变更说明并保存。默认启用范围为本次启用以后首见的告警。“纳入已有告警”仅对本次从停用转为启用的策略生效；修改已经启用的策略会保留原范围。纳入历史告警可能立即产生积压通知，请根据需要选择。
5. 保存成功后会显示新版本，重开页面可核对。另一个管理员抢先保存时返回版本冲突，草稿保留；先核对对方修改，再读取最新版本。最近 20 个版本保留发布者、说明和完整策略快照。
6. 服务每 30 秒检查当前租户的 open/escalated 告警。每个策略每轮更新至多 200 条 SLA，每个层级处理至多 64 条；积压会在后续轮次继续，已到期的多个层级可同轮入队。告警每级只自动入队一次，策略编辑、重启、停用再启用均不会重发已完成层级。
7. 在配置页查看最近检查时间、错误与升级记录。升级级别表示通知已持久化入队；投递状态另外显示待投递、重试、成功、失败、取消或详情过期。外部服务是否收到以渠道回执为准，不把入队当成送达。
8. 确认、解决或抑制告警会停止后续自动升级并取消尚未发送的通知。停用策略或移除层级渠道也会取消未发通知。已开始或已完成的外部发送不能撤回；重新打开告警也不会重发它已经入队的层级。
9. 失败通知在 24 小时内最多自动尝试 8 次。检查通知设置中的错误、地址和密钥后，手动重试失败项，沿用原幂等编号。通知详情保留至多 30 天/4096 条已完成记录；升级入队记录继续保留，旧详情显示“已过保留期”。
10. 只读账号可查看；发布必须使用具有 alerts:read/write 的个人账号。发布者停用、失去权限、需要改密/MFA 或运行模式变化后暂停执行，由有权人员核对并重新保存。没有 PostgreSQL 时可保存停用草稿，不能启用自动升级。

配置入口可直接分享 `/settings?tab=notifications`，告警详情可分享 `/alerts?alert={id}`。接收者仍需当前组织的相应权限。

顶部铃铛提供真实站内消息收件箱，显示当前组织最近 100 条本人有相应资源读取权限的消息，支持正文、关联对象和持久化个人已读状态。标记已读不等于确认告警；告警处置仍需到告警中心。切换组织或账号会清空旧弹窗。无法保存已读时显示错误，可重试，不能用本地成功掩盖服务失败。

## API contract

- `GET /api/v1/alerts/escalation-config`: version, policies, recent history, channel capability summaries, canWrite, automaticAvailable, mockMode, last worker health. Credentials are never included.
- `PUT /api/v1/alerts/escalation-config`: expectedVersion, five routes, reason and optional includeExisting. Route fields: severity, responseMinutes, enabled, tiers. Tier fields: level, overdueMinutes, target, channels. 409 means a stale version; 412 means a missing database/channel prerequisite. OpenAPI contains the request schema.
- `GET /api/v1/alerts/escalation-history?page=1&page_size=20`: tenant-scoped enqueue receipts and current notification delivery metadata. An expired delivery entry means retention ended, not a failed send.
- `GET /api/v1/alerts/escalation-routes`: compatibility projection of the same saved policy; no longer claims every default route is enabled.
- `GET /api/v1/notifications/inbox`: latest 100 delivered in-app messages, permission filtered before limiting; includes personal read state. `POST /api/v1/notifications/inbox/read` accepts `ids` (1..100) and persists personal read markers. This does not acknowledge the underlying alert.

Each automatic escalation atomically commits the alert state, immutable alert/tier receipt and encrypted notification queue. Concurrent workers and process restarts share SQL locks and receipts. Delivery rechecks the current publisher, alert state, channel and policy before sending. Recipient-side idempotency support determines whether a timeout/retry can cause an external duplicate.

## English walkthrough

Configure and test channels in Settings → Notifications. In Alerts → Escalation routes, set a response target per severity, add up to three increasing delays and select enabled channels. Recipients come from channel settings; the role label is descriptive and does not assign users. Enter a reason and save. New activations cover newly seen alerts unless you explicitly include existing alerts; edits to enabled routes preserve their activation scope.

The server checks every 30 seconds in bounded batches. Each alert/tier is automatically queued once across restarts and edits. A backlog can catch up several tiers in one run. Inspect the worker timestamp/error, policy revisions and delivery records. Queued does not mean delivered, and mock receipts do not prove delivery to a real provider.

Acknowledging, resolving or suppressing an alert, disabling its policy or removing a tier/channel stops unsent escalation notifications. In-flight sends cannot be recalled. Failed sends receive up to eight automatic attempts within 24 hours; inspect the channel and manually retry from Notification settings. Completed delivery metadata has a 30-day/4096-record retention bound. A personal user with alert read/write permissions must publish. Revoked publisher permissions or a runtime mode change pause processing until an authorized user reviews and saves again. PostgreSQL is required for automatic execution.
