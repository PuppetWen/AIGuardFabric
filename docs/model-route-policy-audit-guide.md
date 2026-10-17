# 模型路由配置与审计 / Model route configuration and audit

这是候选指南；本增量尚未安装，也未执行新的原生或 SQL 验收。

在 Models 的路由策略区域，先选择已配置的主端点和可选降级端点，再保存。启用策略最多包含一个主端点和 32 个降级端点。权重、策略名称和每日 CNY 预算沿用当前表单含义；旧 `budget_usd_per_day` 字段只是兼容拼写，不进行汇率换算。

编辑时先加载最新版本，手工保存时提交这个版本。版本冲突后保留草稿，重新读取并比较，再明确提交；不要自动把版本号加一，也不要自动重发。

本候选将路由配置与 Configure 审计放在同一次提交中。审计失败或等待期间原权限/令牌失效，SQL 配置、版本和审计均回滚。离线模式在一个配置互斥锁内校验并提交配置及审计；它不提供数据库重启持久性。后台内存投影刷新失败不改变已提交配置的成功事实。

如果 PUT 响应丢失，保留原策略 ID 和提交版本，通过当前路由列表核对该 ID 的权威配置；不要换 ID 重建。POST 由服务器生成 ID，丢失响应时列表匹配不能证明原提交因果关系，不应自动创建第二条记录。此增量没有伪造永久请求编号或模型成功响应。

保存路由只改变下一次请求读取的配置，不调用模型、不验证厂商网络、不宣称云成功。端点此后仍可更改或停用；每次实际请求继续执行当前端点、权限、分类和配额检查。停用旧路由不要求已删除的端点仍存在。

模型路由正文最多 64 KiB（按 JSON 编码字节计数）；超过上限明确拒绝，不截断或静默覆盖。配置成功只表示本地事务与审计已提交，不表示任何外部操作已经完成。

For an existing route, load the latest version, keep the draft, and explicitly save with that version. A 409 requires a fresh comparison; the client must not invent a version or retry automatically. A lost PUT response can be investigated using the original route ID and current authoritative list. A matching POST list item is not proof of the lost request and must not trigger an automatic second create.

The proposed change commits route configuration and its Configure audit together. A refused audit or expired/revoked original authority rolls back the SQL configuration and version. Offline publication has one process-local configuration mutex and no restart durability claim. A compatibility projection failure after commit does not turn the committed business result into a failed save.

Saving a route does not contact a model provider. It does not certify endpoint connectivity or cloud success, and it does not permanently authorize future requests. Subsequent endpoint changes remain subject to the normal request checks. This narrow increment does not claim that all configuration mutations or externally executed operations have atomic audit handling.
