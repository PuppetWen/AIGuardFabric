# 搜索、详情定位与告警处理

## 中文

1. 确认顶部组织，输入名称、编号、规则键或关键词。输入停止 250 毫秒后检索当前组织，最多显示 8 项；精确匹配优先，各资源类别交错展示，避免资产挤占所有结果。
2. 可检索资产（名称、ID、负责人、部门、端点、指纹、标签）、发现（标题、ID、摘要、目标、规则键）、告警（标题、ID、描述）、案件（编号、ID、标题、摘要、负责人、标签）、检测规则及红队用例。只显示当前主体有相应 `read` 权限的资源。停用规则也可检索。
3. 点击结果或用上下方向键及回车，直接打开详情。链接可收藏、刷新或分享；接收人必须登录并具备对应组织权限，不会因获得链接而获得权限。
4. 无匹配会显示空结果；请求失败会显示错误，回车重试。不会用演示数据代替失败查询。输入新词会取消旧请求，切换组织或登录身份会清空旧结果。
5. 告警中心可多选严重等级、风险域、状态，筛选与总数覆盖所有页。点击标题打开详情和关联对象。勾选告警后批量确认、解决或抑制，只有接口保存成功才提示成功；失败项保留勾选并列出原因，可重试。部分成功不会声称全部成功。
6. “已升级”表示告警已触发升级，区别于人工确认；没有写权限时状态控件禁用。更换组织或会话时，未发出的批次取消，已经发出的请求仍可能在原组织完成，可返回原组织刷新核对。

搜索链接：`/assets/{id}`、`/findings?finding={id}`、`/alerts?alert={id}`、`/cases/{id}`、`/rules?rule={key}`、`/redteam?testCase={key}`。
规则和红队用例预览为只读；打开红队用例不会发起战役。

接口 `GET /api/v1/search?q=...&limit=8` 返回数组。`q` 最多 128 个字符，不接受控制字符；`limit` 为 1..50。SQL 每类最多返回 `limit` 条，单条查询超时为 2 秒。当前为字段子串匹配，不含文件正文或语义向量检索；大规模检索的性能压测仍需单独验收。
告警列表 `GET /api/v1/alerts` 支持逗号分隔 `severity`、`state`、`domain`，同字段 OR、不同字段 AND；`q` 支持 ID/标题/描述/去重键，`sort` 支持 `severity`、`dedup_count`、`sla_due_at`、`title`、时间字段，前缀 `-` 为降序。

升级路由、自动执行、投递记录和真实站内消息已单独验证，配置步骤见 [自动告警升级指南](alert-escalation-guide.md)。入队与送达是不同状态；角色标签不自动指派用户。

## English

Confirm the organization before searching. Results are scoped independently by resource permissions and include disabled rules. Queries run after a 250 ms typing pause, show up to eight interleaved results, and prioritize exact IDs/names. Use arrow keys and Enter, or click an item, to open its exact detail. A shared URL still requires login and the relevant permissions.

Network errors remain visible; Enter retries. A new query cancels the old request, and changing organization/session clears prior results. Viewing a rule or red-team case is read-only and never launches a campaign.

Alert filters apply before pagination and counting. Batch updates await each persisted result, report partial failures and keep failed IDs selected for retry. Changing organization/session cancels batches that have not yet been sent; an in-flight write can still complete in its original organization.

The search API accepts at most 128 non-control characters and a limit of 1–50. SQL retrieval is bounded per resource group with a two-second statement timeout. This is field substring search, not file-content or vector search; large-scale performance testing is a separate acceptance task. Editable escalation, automatic execution and the real in-app inbox have separate validation; see the [escalation guide](alert-escalation-guide.md).
