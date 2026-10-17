# 告警自动响应

入口：**案件中心 → 告警自动响应：模板、启停和触发记录**。需要登录用户具有 `cases:admin` 和 `alerts:read`。API Key 不能发布自动响应或冒充人工审批。

## 个人首次使用

1. 点击“新建自动响应”。默认“只建待研判案件”模板不执行处置或调用外部平台；也可选择隔离 Agent、封禁域名、吊销平台 API Key、EDR 主机隔离或 SCIM 身份停用模板。配置初始为停用，处置模板初始要求人工审批。
2. 填写名称、最低告警等级和可选规则键；“只建待研判案件”不需要处置目标。选处置模板时再填写目标。规则键来自关联风险发现，空表示不限。封禁域名不含协议、路径；密钥字段填写平台密钥 **ID**，不是密钥明文。
3. 隔离模板只匹配关联 Agent 的告警；只有一个 Agent 时自动选中。多个 Agent 必须在高级 YAML 的步骤 `params.asset_id` 中指定关联目标，避免误隔离任意第一个资产。
4. EDR/SCIM 模板先在资产详情绑定经过核对的远端编号，并在集成中心启用对应适配器。表单中搜索并选择该资产；页面读取绑定编号与当前配置版本，只需填写处置原因。SCIM 只能选凭据资产。新告警必须关联同一资产。若资产绑定或集成配置发生变更，刷新并保存新版本；服务端在启用和实际执行时都会重新核对。
   对 AI 日志自动生成的 Agent/MCP/模型资产告警，先按[日志接入指南](native-ingest-guide.md#从接入记录到可处理的告警)把事件中的 AI 资产 ID 映射到台账 UUID，并用一条新事件检查告警与发现的资产关联。SCIM 凭据资产的告警须在创建时显式填写其 `asset_ids`；仅有主机名或外部主机编号不会自动绑定资产，无法触发指定资产的处置模板。
5. 展开“匹配预览”，复制一条当前租户的告警 ID，检查规则、关联资产及步骤。预览只检查匹配并展示输入；不创建案件、不执行动作，也不证明目标服务一定可执行。
6. 填写变更说明，开启自动触发并保存。等待接入链路产生新的告警，打开“触发与版本记录”。点击案件链接，在“审批与执行记录”核对目标后批准。EDR/SCIM 在审批前不会调用外部平台。
7. 查看实际步骤结果和集成调用记录，按 [案件处置指南](case-response-guide.md) 验证远端状态。密钥吊销不可解除；EDR 解除和 SCIM 身份重新启用由对应外部平台处理。

真实 Agent/MCP 红队任务只有在**已判定命中**时生成关联发现和新告警；模拟或无结论不会触发。想自动建待研判案件时，先启用“只建待研判案件”模板，再发起真实目标任务；也可在启用前用已有告警预览匹配，但启用不会补跑旧告警。战役完成后从“红队中心 → 战役详情 → 查看关联告警与案件”检查告警，再从告警详情进入案件。这个模板只创建案件及无副作用的记录步骤，后续处置由人员在案件中决定。若不启用模板，可从待审发现手工确认建案。

可在高级模式输入完整 YAML 或 JSON。表单支持模板的单步骤配置；复杂 YAML 保留在高级模式，选择起始模板会重建表单。

## 企业运行规则

- 可勾选“双人复核”，要求发布者以外的管理员审批。单个管理员可配置和演练，但不能替代另一人的批准。
- 后台按发布者当前身份和权限重新校验；停用账号、收回角色、撤销跨租户权限后不再沿用旧权限。实际执行每步还会检查所需动作权限。
- 每次启用只处理该时间以后**新建**的告警。重复上报合并到原告警不会重复触发，编辑版本不重跑已经评估的告警。停用期间创建的告警不会在重新启用时补跑。
- 触发匹配时，如果告警已有未解决案件则复用；否则创建案件。已解决/关闭案件不自动重开，不活跃或被抑制的告警记录为跳过。
- **停用只停止后续提交**。已提交、待审批或等待中的执行任务需要在对应案件取消；已完成动作须按处置说明解除，不能靠停用配置回滚。
- SQL 模式将案件、告警归属、任务与触发结果同事务提交。跨实例并发、重复告警和重启不会为同一配置/告警重复创建任务。较晚提交的事务不依赖移动时间游标，因此不会因提前扫描而漏掉。
- 显式内存模式仅用于演示，重启丢失配置与记录；界面有提示。持久运行使用 PostgreSQL。
- 每租户最多 50 个配置，已停用的配置也占名额；停用不会释放容量。达到上限时，复制需要保留的草稿，返回列表选择“编辑 / 启停”修改已有配置。现有配置编辑不占新名额；界面不提供删除配置释放名额。最近 20 个配置版本可查询；执行任务另存不可变剧本/目标快照，历史按需读取。

## 失败与恢复

“已提交任务”表示已经保存任务，不等于动作完成。“触发失败”可展开查看原因与最近 20 条评估/重试记录；修复权限或配置依赖后，在同一配置版本点击“重新评估触发”。已提交任务不能再次从触发记录重试，须到案件查看实际结果。更改了剧本版本的旧失败记录不会自动执行新动作，必要时在案件内重新提交经过核对的剧本。

多人编辑采用版本冲突检查。冲突不会覆盖当前输入；复制需要保留的内容，关闭弹窗、刷新并重新打开配置后再核对提交。模拟/真实模式发生变化时停止旧配置触发，需重新核对并保存配置。

新建返回“每租户最多 50 个配置”时是容量不足，不是剧本 JSON 格式问题。名称、高级 YAML/JSON、变更说明与启用/审批选择都保留；不会自动提交或启用。其他 HTTP 400 仍可能是剧本、原因或目标校验失败，应按具体错误修正。搜索或当前一页的数量不是租户总容量。

固定域名/密钥模板对每条匹配告警使用同一配置目标；它们不会从任意告警文本猜测域名或泄露凭据。规则域、资产类型和 CEL 条件可在高级 YAML 的 `trigger` 中设置；匹配预览使用告警等级、风险域、关联发现规则键及资产类型。

## API

| 方法 | 地址 | 用途 |
|---|---|---|
| GET / POST | `/api/v1/soar/automations` | 分页查询 / 新建 |
| GET / PUT | `/api/v1/soar/automations/{id}` | 包含历史的详情 / 版本化修改 |
| GET | `/api/v1/soar/automations/templates` | 内置模板 |
| POST | `/api/v1/soar/automations/preview` | `yaml` 或 `playbook` + `alert_id`，无副作用 |
| GET | `/api/v1/soar/automations/{id}/deliveries` | 分页、关键词搜索触发记录 |
| POST | `/api/v1/soar/automations/{id}/deliveries/{delivery}/retry` | 当前 `expected_version` 下重新评估失败 |

创建/修改请求包含 `yaml` 或 `playbook`、`enabled`、`separate_approver`、`reason`、`expected_version`。新建版本为 0；后续提交已读取版本，成功后递增。工作流等待、审批和中断恢复接口见案件处置指南。

## English quick start

The tenant limit is 50 configurations, including disabled ones. Disabling does not free a slot. At capacity, copy the draft you need, return to the list and use **Edit / enable** on an existing configuration; updates do not consume another slot. The capacity rejection keeps the name, YAML/JSON, change reason and enablement/review choices. It does not save or enable automatically. Other HTTP 400 errors can indicate invalid playbooks, reasons or targets; read the actual error. Search results and one page of records do not establish tenant capacity.

Open **Cases → Automatic alert response**. Choose a template, set severity, rule keys and a concrete target, then preview against a tenant alert. Preview creates no case and makes no external call. Save and enable to process newly created alerts. Open trigger records and follow the case link to approve and inspect each step. Enterprises can require a different administrator to approve. Publishers and executors must retain their current permissions.

The default **case for human triage** template only creates a linked case; it performs no response action or external call. Enable it before a real Agent/MCP campaign if you want an evaluated hit to open a case. A hit creates a pending finding and an alert in the campaign transaction. Open the campaign's linked alerts, then follow the alert to its findings and case. Simulation and inconclusive results do not create alerts. Existing alerts are not backfilled when a template is enabled.

Each configuration/alert identity is evaluated once; duplicate occurrences and restart do not submit another run. Disabling stops new submissions, while existing runs must be cancelled in their cases. Alerts created while disabled are not backfilled. Failed evaluations may be retried explicitly at the same revision, with history retained. PostgreSQL commits the case, run and receipt together. Memory demo mode loses records on restart. Configuration editing retains inputs after a conflict; reopen the latest revision before resubmitting.

For EDR/SCIM automatic response, first bind the verified remote ID in the asset details and enable the corresponding integration. Search for the asset in the form; its binding and current configuration version are loaded for you. Enter the response reason, preview a linked alert, then enable. SCIM accepts credential assets only. A newly created alert must link that exact asset; the run waits for human approval before any external call. Reopen and save a new automation version after changing the asset binding or integration configuration. Verify the remote outcome in the case and integration receipts; see the [case response guide](case-response-guide.md) for recovery steps.

For Agent/MCP/model alerts created from normalized AI events, map the event's `ai.agent_id`, `ai.mcp_server_id`, or `ai.model_endpoint_id` to an existing asset UUID of the same kind in the current tenant. Check a new event's asset links before enabling an asset-specific response. SCIM credential alerts need that credential asset in `asset_ids` when the alert is created. Host names and external host IDs do not grant an asset binding.
