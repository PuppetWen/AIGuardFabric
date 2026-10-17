# 规则发布、权限与冲突处理

在“操作指南 → 运维与排查 → 规则发布”查看页面内指南。个人可使用自己的管理账号；企业应按组织分配规则维护和发现处理权限。

1. 选择组织，在“检测规则”中按名称或 key 搜索。只读用户可以查看 YAML、历史和详情，不能发布、恢复、调整启停/灰度或执行样本。管理者需 rules:write，处理发现状态需 findings:write。
2. 点击“新建规则”，唯一 key 自动生成，灰度默认 0%。填写检测条件及至少一个正样本、负样本。0% 不匹配正常扫描/网关请求；发布和手工回归仍执行样本。
3. 校验并发布，确认样本结果后按 5% → 25% → 100% 逐步扩大范围。已有规则不得修改 key；复制成新规则请从新建入口填写另一个 key。
4. 409 表示期间已有修改。草稿仍在编辑器中，先复制需要保留的内容，点击加载最新版本并确认替换，合并后再发布。网络失败也应先核对当前版本；不要把超时视为保存失败或盲目重复发布。
5. 最近 100 个版本保留 YAML、操作人和时间。“查看内容”仅载入编辑器；“恢复”重新校验样本并生成新版本，保留旧历史。恢复会使用该版的启用状态与灰度，请先核对。
6. 切换组织/账号会重置表单和列表状态；已发出的请求仍属于原组织，未发出的操作不会自动转移。需要保留的草稿请先复制。

API 使用 JWT 或授权 API Key 并带正确租户。列表返回 can_write，规则条目返回 read_only，详情返回 can_write。服务端仍独立校验所有写操作。

- 新建：POST /api/v1/rules，body 含 yaml、expectedVersion: 0。
- 更新：同一 POST，body 含 yaml、sourceKey（原 key）、expectedVersion（GET 详情 rule.version）。
- 启停/灰度：PATCH /api/v1/rules/{key}，body 含 enabled 或 rolloutPercent，以及 expectedVersion。
- 历史：GET /api/v1/rules/{key}/versions。
- 恢复：POST /api/v1/rules/{key}/versions/{version}/restore?expectedVersion={当前版本}。

兼容旧客户端的版本字段是可选的；省略时不具备旧版本覆盖保护。控制台始终提交版本。新版本必须重新读取，不能把历史版本号当作恢复请求的当前版本。

## English

Choose the organization and open Detection rules. Readers may inspect YAML and revision history. Rule publication, enablement, rollout, sample execution and restoration require rules:write; finding state changes require findings:write.

New rules have unique keys and start at 0% rollout. Edit the conditions and positive/negative samples, publish, run regression and expand gradually. Existing keys cannot change. A stale save returns 409 and keeps the draft; copy it before loading the latest revision, merge and republish. After a timeout, check the server version before retrying.

History keeps the latest 100 revisions. Viewing contents does not publish; restoring validates samples and creates a new revision using the selected content, including its enablement and rollout. Switching organizations or sessions resets old forms.

For API clients, send expectedVersion: 0 for creation, the loaded rule.version for edits/patches, and the current version as the restore query parameter. Include sourceKey for edits. Version fields remain optional for legacy clients, which do not get conflict protection when omitting them.

## 页面访问与角色说明

左侧目录按服务器返回的当前权限显示。直接输入无权限页面地址时，页面会列出缺少的权限并提供重新检查及指南入口；不会继续加载受限页面的数据。登录、切换组织后重新查询权限，停留页面每 30 秒刷新，回到窗口也会重新检查。服务器在每次请求时独立授权，界面刷新间隔不延迟权限撤销。

内置 viewer 仅能读取资产、发现、告警、案件和报表，不包含 rules:read。redteam-engineer 可读取规则但不能修改规则；该角色还有红队执行、发现处理等权限，不应只为查看规则而随意授予。企业应按职责选择角色或给自动化工具分配范围明确的 API Key。

部分页面组合多个资源：红队页面需 redteam:read 与 assets:read；日志接入页面需 sources:read 与 parsers:read；运行时页面需 policies:read、quotas:read、settings:read。接口权限未改变。账号安全和静态操作指南始终保留入口。

The sidebar follows the server's evaluated access capabilities. A direct restricted URL shows the missing permissions without mounting the protected page. Capabilities refresh after sign-in/organization changes, every 30 seconds and on window focus; the server still authorizes every request immediately.

The built-in viewer role reads assets, findings, alerts, cases and reports, but does not include rules:read. The redteam-engineer role reads rules without modifying them and has additional red-team/finding powers; do not grant it solely to obtain rule visibility. Assign roles or scoped automation keys according to duties.
