# 事件分析故障恢复

## 从接入到告警

日志接收成功表示原文和事件已经保存。消息投递、规则分析和通知是后续独立步骤：接入管理分别展示消息待确认数量、分析进度和失败状态。关闭 NATS 时，已提交的 SQL 事件仍通过数据库扫描自动分析。

合法消息的分析失败时，服务先确认规范事件及恢复状态已持久保存，再确认消息，转由数据库队列负责退避、隔离和恢复。重投不会消耗已暂停或等待中的额外尝试次数。格式错误、路由不匹配或不存在对应 SQL 原事件的消息，加密持久保存到平台异常消息队列后确认；保存失败则不确认。平台管理员按 [异常消息处理指南](broker-quarantine-guide.md) 排查发布方、查看证据及人工恢复。不能把消息确认数当作分析成功数。

## 处理失败事件

1. 打开 **接入管理 → 查看失败事件与恢复**，选择“待恢复”。可按事件 ID 或错误代码搜索，结果在服务器分页。
2. 查看错误代码、失败次数和“查看来源事件”。用事件 ID 对照服务日志，检查规则输出、数据库连通性或关联窗口。页面不会回显依赖错误中的原始凭据。
3. 临时不需要继续尝试时选择“暂停重试”。暂停阻止后续尝试，正在完成的事务仍可能成功。
4. 修正规则、缩小关联窗口、恢复数据库或正确的加密配置后，选择“重新排队”。此操作重新启动最多 8 次自动尝试；累计失败数保留。按钮成功只表示已排队，等待状态变为“已恢复”。
5. 选择“已恢复”可查看历史失败记录；“恢复历史”保留操作者、时间和原版本。恢复与已完成回执去重，重复投递和并发重试不会重复创建已提交的发现或告警。

| 状态 | 行为 |
|---|---|
| 自动重试 | 首次失败后等待 10 秒，再按指数退避，最大间隔 5 分钟 |
| 已隔离 | 连续失败达到 8 次后停止自动尝试，保留事件等待人工修复 |
| 已暂停 | 操作员暂停；选择重新排队恢复 |
| 已恢复 | 已原子提交分析回执、发现和告警；历史仍可查询 |

读取需要 `sources:read`，操作需要 `sources:write`。不同组织相互隔离，切换组织会清空当前抽屉和结果。操作包含版本号；如果其他人或后台先改变了状态，返回 409 并刷新列表，请核对新状态后重新选择，平台不会自动覆盖。

恢复使用当前发布的规则。要修改原始事件，先在解析器预览中验证修正，再通过原日志回放生成可追溯的新事件；不要直接改写已有证据。连续失败隔离不会被记成分析成功，也不会删除原始数据。

本界面管理规范 SQL 事件的分析故障；消息发布队列及不符合事件协议的 broker 消息是不同流程，不能仅凭本界面为空推断它们全部健康。

## English quick start

Open **Ingest → Failed events and recovery**. Inspect the error category and source event, then fix the rule, window, database or configuration. **Pause retries** stops future attempts. **Requeue** starts another retry cycle using current rules; it does not itself mean analysis succeeded. Eight consecutive failures quarantine an event. Completed analysis retains its failure and operator history. Tenant isolation and version checks protect concurrent operations, and committed findings/alerts are not duplicated by replay.

## 本地验证

普通接口门禁：`cargo test -p agf-api --test analysis_operations`。

真实数据库专项需设置专用 `AGF_TEST_DATABASE_URL`，库名必须以 `agf_requirements_test_` 开头；运行 `cargo test -p agf-api --test analysis_operations --test event_analysis_recovery -- --include-ignored --nocapture`。测试验证真实 SQL 写入失败、8 次隔离、正常事件不受阻、只读及跨租户拒绝、并发版本冲突、进程状态重建、恢复去重和持久操作历史。不要指向业务数据库。
