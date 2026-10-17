# 消息服务异常消息处理

## 入口及权限

以平台管理员个人账号登录，打开 **接入管理 → 平台异常消息与恢复**。
此队列覆盖整个平台，不随右上角组织选择器过滤。普通组织管理员、只读人员和 API Key 均不能查看。
原因是这类消息的租户声明尚未验证，不能按消息自报的组织分配查看权限。

这里处理消息格式无效、主题与事件租户或等级不匹配、SQL 原事件不存在、组织不存在。
合法且有 SQL 原事件的分析故障进入另一入口 **查看失败事件与恢复**。
消息发送失败则查看接入页的“事件投递”状态，检查 NATS 连接、存储容量和投递日志。
三个流程的状态不能互相代替。

## 处理步骤

1. 用消息 ID、SHA256、原因代码或消息流名称筛选，默认显示待处理，支持服务器分页。
2. 根据原因检查发布方、来源接入设置及数据库。列表不展示消息原文。
3. 必须核对原始内容时点“查看原始证据”，此操作记入历史。原始字节使用 Base64 显示，可下载 JSON；解码后计算 SHA256 并与 `payloadHash` 比较。内容可能含敏感日志，仅在受控环境保存。
4. 数据库原事件已恢复、数据库/密钥配置已修正时，填写理由并“人工重试”。重试只使用原消息引用找到的规范 SQL 事件；页面不能编辑原始消息、替换组织或插入新证据。
5. 对格式或路由错误，应修复发布方，通过原接入源提交正确事件；确认新事件正常后，在旧消息上选择“关闭并保留证据”，填写处理依据。
6. 查看“处理历史”核对操作者、理由、版本和结果。关闭和成功重试都保留原文及历史。过期页面操作返回 409，输入保留，核对新状态后重新选择。

| 原因代码 | 核对内容 |
|---|---|
| `invalid_payload` | 发布方是否发送兼容的归一化事件；不能将任意原始日志直接发布到事件主题 |
| `subject_mismatch` | 主题必须为 `agf.events.<tenant_uuid>.<severity>`，与事件一致 |
| `missing_event` | 同一组织下的事件 ID 与时间必须已提交；先写证据再发布引用 |
| `unknown_tenant` | 组织是否仍存在，来源是否配置正确；不要为了重放不可信消息而随意创建组织 |
| `encryption` | 所有实例须使用原持久化主密钥；更换密钥不能修复旧证据 |
| `retry_interrupted` | 人工重试中断或服务重启；核对分析回执后再决定是否重试 |
| `sql_recovery_owns_retry` | 已移交“查看失败事件与恢复”，不表示分析已经成功 |
| `analysis_completed` | 规范 SQL 事件分析已经完成，包括已完成的重复引用 |

## 持久化与中断

异常消息的完整原文与主题加密存入 PostgreSQL 后才确认消息。
数据库、加密或保存失败时不确认，消息服务保留投递责任。
同一消息流、序号、主题及原文字节重复投递不新增记录，也不会重新打开已关闭项；新投递序号会单独记录。
不要通过删除消息流或清空数据库“解决”异常，否则可能丢失未处理证据。

人工重试先持久化 120 秒租约和操作记录，处理限时 45 秒。
服务重启或请求中断后，不自动重放不确定的人工操作；再次打开队列时，过期租约转回待处理并增加中断历史。
规则分析的已提交回执去重，重复恢复不会重复生成已提交的发现和告警。
关闭消息不是删除操作。当前界面不提供原始证据清除；按组织保留策略管理数据库备份和容量。

## English quick start

Open **Ingest → Platform message quarantine** with a human platform administrator account.
This global queue is independent of the selected tenant; tenant claims inside invalid messages are untrusted.
Search by ID, SHA256, stream or reason. **Inspect evidence** explicitly decrypts the original bytes, records the inspection and allows a Base64 JSON download.
Repair the publisher or restore the canonical SQL event, then use **Manual retry** with a reason.
Retry cannot edit payloads or override tenant ownership. For malformed data or routing, resubmit through the ingest source and use **Close and retain evidence** on the old item.
Successful handoff to SQL recovery is not analysis completion; inspect **Failed events and recovery**.
Stale versions return 409 without overwriting the reviewed action. Expired manual retries return to review; history and encrypted evidence survive restart.

## 验证命令

使用专用测试数据库 `AGF_TEST_DATABASE_URL`（库名 `agf_requirements_test_*`）及本地 `AGF_TEST_NATS_URL`：

```powershell
cargo test -p agf-api --test broker_quarantine -- --include-ignored --nocapture
```

测试会创建独立的 `AGF_REQUIREMENTS_*` 消息流，不应指向业务数据库或复用业务消息流。
