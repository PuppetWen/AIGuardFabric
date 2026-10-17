# 报表与通知操作指南

## 个人用户：先生成一份报告

1. 打开左侧“报表中心”，选择内容、统计窗口和格式。PDF 适合阅读；CSV 适合表格分析；JSON 适合程序处理。
2. 生成后在列表下载，核对租户、统计时间、数据和文件内容。下载要求登录并具有 reports:read 权限。
3. 需要每日生成时创建定时计划；不选通知渠道则只在平台保存文件。

## 企业用户：配置收件渠道

1. 在“设置 → 通知渠道”填写实际收件人、服务地址和凭据，保存并启用。凭据加密保存，不会再次回显；同一投递地址下留空保留原值。更换 Webhook 地址、短信网关或 SMTP 主机等投递目标时，必须重新填写该渠道已保存的凭据，避免旧密钥发往新目标。
2. 点测试。测试会先保存当前编辑再发送一条消息；模拟模式会明确显示“模拟”，不能据此判断真实送达。
3. 到报表计划中选择已启用的渠道。报表操作员只读取渠道名称和启用状态，看不到收件人或密钥。
4. 通知发送“报表已生成”的提示，文件仍要求登录下载。收件人需要平台账号及所属租户的报表读取权限。
5. 报表是显式订阅，不受告警最低严重等级过滤；停用渠道会停止后续投递。

多人同时编辑渠道时，旧版本保存会返回 409，页面保留草稿并禁止继续以旧版本重试。先复制要保留的修改，再确认“重新加载”，对照最新配置重新填写；重新加载会丢弃当前草稿。API 列表返回 `version`，新建可不传版本或传 `expectedVersion: 0`，后续保存必须提交当前 `expectedVersion`。

## 时间规则与修改计划

cron 使用 UTC，五段依次是分、时、日、月、周：

| cron | 含义 |
|---|---|
| 0 0 * * * | 每日 UTC 00:00，即北京时间 08:00 |
| 30 1 * * MON | 每周一 UTC 01:30，即北京时间 09:30 |
| 0 0 1 * * | 每月 1 日 UTC 00:00 |

主服务每 15 秒检查一次。停机期间错过的周期不补跑；已经领取但失败或中断的生成任务会按原窗口重试。
统计窗口是相对于实际计划执行时间向前计算，例如 7 天为最近 7 天的数据。

编辑按钮可修改名称、内容、格式、统计窗口、cron 和通知渠道。编辑保留已有报告及当前暂停状态。
多人同时编辑、启停或删除同一计划时，所有修改都核对页面读取的版本。另一位管理员先修改后，旧页面操作返回冲突且不覆盖新状态；关闭表单、刷新计划列表、核对最新内容后再操作。删除也需要当前版本，不会凭旧页面确认直接删掉新计划。
执行中的计划等待本次完成后才能编辑或删除。暂停不会取消已经开始生成的报告；删除计划也不会删除历史文件。
使用“立即生成”验证编辑结果，修改内容后即使同一分钟再次生成，也会得到匹配新配置的报告。

生成成功后，可在“审计日志”按 `export` 和操作人筛选：手工生成记实际操作员，定时生成记 `agf-report-scheduler`，目标编号与报表详情一致。数据库模式下，报表文件记录与成功审计共同提交；如果其中一步失败，不会留下半成品。计划生成失败后会按原统计窗口重试；同一计划、同一分钟及同一内容版本只保留一份报表和一条成功审计。需要重新统计当前数据时，请修改计划内容或等待下一个执行窗口。

## 投递状态与重试

“设置 → 通知渠道”上方显示投递记录、尝试次数、最近错误和下一次重试时间。每 10 秒刷新一次。

- 消息正文加密入队后发送，配置数据库时可以跨进程重启恢复；无数据库的离线模式仅保存于内存。
- 同一租户、对象、渠道及严重等级沿用同一个投递编号；等级升级会产生新的通知。站内消息按编号去重。
- 每个渠道每分钟最多 60 次投递尝试。失败按指数退避，最多尝试 8 次或持续 24 小时；最长单次退避 15 分钟。
- 修复地址、凭据或网络后，可以对失败或等待重试的消息点“重试”。后台使用该渠道当前配置，保留原编号和累计尝试记录。
- 停用/删除渠道取消待发送消息。外部渠道从模拟切换到真实（或反向切换）后，旧模式的队列任务不会自动对外发送，需确认后重新发起。
- 每租户最多 1024 条待处理消息，队列满时会明确拒绝新增；完成记录最多保留 30 天或最近 4096 条。
- 网络中断可能发生在外部服务已接受、平台尚未收到回执之间。重试沿用幂等编号；不支持幂等的外部渠道仍可能重复收件。

如报表生成失败，先检查数据库和服务日志；如报表生成正常、通知失败，检查投递记录及渠道配置。
不要通过删除报表或重建计划解决渠道认证错误。

## English: notification channel edits

In Settings → Notification channels, configure the recipient, delivery destination and credentials, then save and enable the channel. Saved credentials are encrypted and never displayed again. A blank credential field preserves it only while the delivery destination stays the same. When changing a webhook URL, SMS gateway or SMTP server identity, re-enter all stored credentials for that channel so an old secret cannot be sent to a new destination.

Channel lists include `version`. Creation may omit `expectedVersion` or set it to 0; later saves require the current `expectedVersion`. HTTP 409 means another administrator changed the channel. The page keeps your draft and blocks another stale save. Copy any changes you need, confirm Reload, review the latest configuration, and apply your changes again. Save and send test performs a real outbound delivery unless mock mode is shown.

## 调度器上报云监控

真实 CMS 自定义指标需要部署配置 AGF_CMS_GROUP_ID，值为云监控中已创建的应用分组 ID。
在项目 .env 中配置后重建 agf-scheduler 服务；仅填写 AK/SK 不足以决定指标所属分组。
无凭据或模拟模式会如实显示 Mock，不会标记为真实云监控上报成功。


## 中文 PDF 与离线验证

新生成的 PDF 内嵌 Noto Sans CJK SC 字体子集，无需在服务主机或阅读器电脑安装中文字体，也不会在生成时访问外网。中文、英文和字体覆盖的罕见汉字可复制、搜索；文件保存原始字节，升级后下载历史报表不会重新渲染或改变其哈希。

导出按字形实际宽度换行，表格自动分页并重复表头。彩色 Emoji、复杂文字连写不在该字体的覆盖范围；缺失字形会显示字体的缺字框，原始 Unicode 仍保留在文本映射中。

开发或气隙环境可用平台同一编码器验证自己的 Markdown：

```powershell
cargo run -p agf-api --example export_report -- input.md output.pdf
```

输出路径必须尚不存在，以免覆盖已有文件。字体来源、SHA-256 和 OFL 许可在 `crates/agf-api/resources/fonts/README.md`，相关许可证随项目保留。
