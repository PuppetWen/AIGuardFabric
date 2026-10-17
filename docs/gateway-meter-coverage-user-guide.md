# 模型计量覆盖与预算核对

在 `/models` 先确认当前组织，点击刷新查看费用图、计量记录以及当前节点累计投影提示。读取不调用模型、不修复记录、不写审计、不续期。

费用图按当前组织**保留的真实 UsageRecord**汇总，排除模拟记录。它不是每日预算账本，也不是厂商账单。一次请求可产生 embedding 与 chat 两条组件记录；计量条数不是模型 HTTP 请求次数。已知实际用量计入组件费用，未知上游用量可能留在原持久账本中作为保守费用而没有实际 UsageRecord。

若显示“当前节点累计投影不完整”，现有小计仍可用于查看已验证的部分，但旧/legacy 记录、缺失或损坏的证据、超出有界扫描等情况使整个历史范围未确认。后台没有迁移旧费用、重扣费或删除历史。节点状态不是其它组织的费用数据，也不表示当前组织的保留记录查询必然失败。

启动覆盖证明在同租户 RLS 快照中最多检查 512 条 Usage、512 条加密 Fact 与 8 MiB 正文。超过范围只标记不完整，不用前缀伪装全量。分组合并只压缩显示粒度，不能单独证明历史覆盖完整。状态读取失败时范围为未知，不能当作完整零费用。

核对预算使用原模型请求 `x-agf-attempt-id` 的持久结算回执与原 gateway/runtime ledger。仅服务器允许的 `pending-audit` 可由原身份明确本地恢复；恢复不会重发模型或 embedding。参见页面“费用结算查询与恢复指南”。不要根据投影差额补扣历史费用。

## English

At `/models`, check the tenant and refresh the cost charts, records, and node projection notice. Reading calls no model, repairs no record, writes no audit, and renews no lease.

Charts total **retained real UsageRecords for the current tenant** and exclude mocks. They are neither daily budget ledgers nor provider invoices. One request can create separate embedding and chat component records; the record count is not the number of model HTTP requests. Unknown usage can retain conservative charges in durable ledgers without an actual UsageRecord.

An incomplete node projection preserves verified subtotals while historical coverage remains unconfirmed: legacy rows, missing or damaged evidence, or bounded scans can cause this. No historical fees are migrated, charged again, or deleted. This node health flag contains no other tenant’s amounts and does not itself mean that the retained-record query failed.

Coverage is checked in a tenant-RLS snapshot, bounded to 512 Usage rows, 512 encrypted Facts, and 8 MiB. Exceeding a bound is incomplete, never a complete prefix. Group merging affects display detail and does not prove coverage. A failed status read means unknown, not authoritative zero cost.

Use the original `x-agf-attempt-id` settlement receipt and durable gateway/runtime ledgers to reconcile budgets. Only server-permitted pending-audit can be explicitly recovered by the original identity, without another chat or embedding call. Follow the page’s settlement guide. Never recharge historical fees from a projection difference.
