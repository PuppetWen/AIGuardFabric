# Skill 评审与白名单

适用：个人维护本地 Skill，或企业按租户、负责人和数据分级管理 Skill 台账。页内和“操作指南 → 日常操作与排障 → 资产台账”提供同样的中英步骤。

## 日常操作

1. 先选择顶部组织。个人可在资产台账登记 Skill；企业可由终端采集器自动发现，或先提交上线申请。
2. 打开“Skill 授权”。搜索覆盖名称、负责人和标签；状态筛选、名称/风险排序与分页均在服务端完成。试用、申请、评审和变更中的资产显示待审批。
3. 点击“查看 / 评审”。表单只提供合法下一步：申请中 → 评审中 → 试用 → 生产。生产资产先进入变更中，再重新批准；拒绝和归档是终态。
4. 填写负责人、部门、数据分级和评审说明。批准、拒绝和归档显示实际认证操作人及保存时间。没有历史审批证据的旧数据保持未知，不根据资产创建时间推算。
5. 点击“查看声明”维护域名和绝对路径。域名可写 api.example.com 或 *.example.com，不含协议、端口、用户信息或路径。路径可写 /srv/data 或 C:\Program Files\Tools\*；按回车添加，空格保留，不接受 .. 父级跳转。每类最多 100 项，单项最多 1024 字节；域名部分最多 253 字节。重复项规范化去重。
6. 保存两个空列表会清空声明。只读角色可查看但不能保存；归档/拒绝后白名单只读。切换组织或账号关闭原表单。
7. 遇到 409 冲突时，草稿保留且停止继续提交。核对当前记录，点击“加载最新版本”，明确确认丢弃草稿后重新编辑。采集上报更新资产修订时间，也可能导致冲突。
8. 其他保存失败会显示服务端原因并解除保存状态。修正输入后重试；刷新列表读取最新结果。

## 企业协作与边界

- 读取需要 skills:read，评审和白名单修改需要 skills:write。服务端每次重新校验权限和租户；页面能力来自当前会话授权。
- 生命周期、评审人/时间/说明与资产变更记录在同一数据库事务中保存。并发更新使用 expected_updated_at；控制台始终提交读取的原修订值。内存模式也在同一锁内检查并修改。时间使用稳定精度，避免数据库舍入引起误冲突。
- 旧 API 客户端可省略 expected_updated_at，但没有过期表单保护。所有评审必须提供 note，生产必须明确提供 owner 和 data_class；原先跳过生命周期的调用将返回 409。
- 采集器不能写入 agf_ 前缀的服务端治理证据，也不能覆盖已评审的 whitelist；这些值应通过专用评审接口维护。
- 本页维护台账状态与声明白名单。它不自动安装、停止外部应用、回收凭据或执行出网拦截。需要实际阻断时，在对应端点、API Key 和运行时策略中配置并使用测试账号验证。目录内容变化也应按资产治理指南核对。

## API

先 GET /api/v1/skills/{id}，读取 skill.review.updatedAt、lifecycle 和 allowedNext。评审提交：

~~~json
{
  "to": "production",
  "expected_updated_at": "2026-09-22T10:00:00Z",
  "owner": "alice",
  "department": "Finance",
  "data_class": "confidential",
  "note": "已核对用途、访问范围和数据分级"
}
~~~

POST /api/v1/skills/{id}/status 支持准确的 to 生命周期值，也保留 status/state 的 pending、approved、rejected、revoked 别名。多个字段不一致返回 400。pending 别名对应 under-review，不跳过合法状态约束。

PUT /api/v1/skills/{id}/whitelist 必须提供 domains、paths 两个数组，以及建议始终携带的 expected_updated_at。缺少数组不会被解释成清空。接口返回完整 Skill 对象，与列表/详情同一投影。500 等不确定失败后先刷新核对记录，不盲目重复提交。

## English guide

Select the organization, register or discover the Skill, then open Skill grants. Search, status filters, name/risk sorting and pagination cover the whole inventory. Discovered Skills start in Trial and are pending approval.

View / review shows legal transitions: Requested → Under review → Trial → Production. Production changes go through Changing before approval. Enter the owner, classification and review note. Approval, rejection and archival record the authenticated actor and time. Archived and Rejected are final states.

View declaration edits domain and absolute-path allowlists. Press Enter to preserve spaces in Windows paths. Domains may use a leading *. and contain no scheme, port or path; paths cannot contain .. segments. Up to 100 entries per list, 1024 bytes per entry and 253 bytes per domain. Two explicitly empty lists clear the declaration.

A conflict retains the draft and stops resubmission. Compare the current record, explicitly confirm loading the latest revision, then edit and save again. Collection updates may also change the revision. Permission loss disables saving; changing organization/account closes the old editor.

Reads require skills:read; writes require skills:write. Review evidence and history commit with the asset. Collectors cannot override reserved governance metadata or reviewed allowlists. API callers should send expected_updated_at; omitting it opts out of stale-form protection. Notes are required for reviews, and production requires explicit ownership/classification.

This maintains inventory declarations. Configure and verify installation, process controls, credential revocation and egress enforcement separately in the appropriate runtime or endpoint controls.

