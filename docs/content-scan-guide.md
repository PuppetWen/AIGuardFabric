# 内容扫描 / Content scans

## 个人用户

打开“风险发现 → 内容扫描与任务”，填写任务名称，选择提示词、配置、文件内容等类型，粘贴待检测文本并提交。可不关联资产。留空安全域时按内容类型选择；界面支持全部 11 种类型。

每 3 秒更新任务历史。展开成功任务后点击“发现”查看证据、修复建议；核对后再在风险发现中标为已验证、误报或已修复。无命中并不证明资产安全；本次评分只覆盖本次内容，不覆盖整项资产，也不会把资产的未评估风险分改成 0。

## 企业用户

先核对顶部组织，搜索并关联当前组织中已登记的资产。读取任务需要 scans:read，提交/取消需要 scans:execute，关联资产还需要 assets:read。没有对应权限时入口隐藏或操作禁用；服务端始终重新验证。其他租户或不存在的资产返回 404。

扫描不会执行内容中的命令，也不会连接目标设备。任务表只保存摘要，不保存提交的原文；生成的发现可能保留命中证据。请遵循组织对检测数据的授权和分级要求。可勾选模型二次研判；实际使用 Mock 的研判在任务中明确标注，未触发研判时没有该标签。

模型二次研判还需 models:write。开启后，生产模式使用“模型网关”中的当前组织端点和默认路由，调用受运行时策略、内容过滤、数据分级和配额控制，并记录真实用量。先配置符合数据分级的模型端点，再启用研判；关联资产的更高分级不会被表单降低。AGF_MOCK_MODE=1 使用标注为 rule-based-judge 的离线规则研判，不发送外部请求。

任务展开区显示完成研判次数、Mock 标记和降级提示。未配置端点、被策略/分级/配额阻止、超时或模型返回无效 JSON/证据引用时，保留规则结果，增加失败计数，不伪造模型结论。整体任务仍受 120 秒期限限制；超过整体期限没有已提交结果。模型调用一旦发生，取消任务不能撤销已经消耗的上游用量。

安全研判跳过模型响应缓存，每次任务获取当前结论；同一文本的再次提交仍可能产生模型调用用量。旧任务不会补写新的研判次数或伪造历史模型结论。

## 批量接入

向 POST /api/v1/scans 提交以下结构；使用当前组织的 Bearer Token 或 X-AGF-Key，并传 X-AGF-Tenant。不要把密钥直接写进版本库或共享文档。

    {
      "job_name": "configuration-review",
      "wait": false,
      "use_llm_judge": false,
      "domains": ["credential-leak", "tool-abuse"],
      "targets": [
        {"label": "application-config", "kind": "config", "text": "sample configuration"}
      ]
    }

返回 task_id 后轮询 GET /api/v1/scans/{task_id}，检查 terminal 和 job.state。成功时 finding_ids 对应风险发现详情 ID。GET /api/v1/scans 支持分页、名称/ID 搜索、state 筛选和字段裁剪。取消使用 POST /api/v1/scans/{task_id}/cancel。接口结构见 /openapi.json。

- 每批 1–100 项，单项文本 1 MiB、累计 4 MiB；任务/目标名称最多 200 个 UTF-8 字节，安全域最多 5 项。
- 编码后的整个 JSON 请求体最多 16 MiB；大量 JSON 转义字符也计入请求体上限。
- 任务创建后最多执行 120 秒；取消与完成使用同一行锁，先提交者生效。完成后的取消不会撤销发现。
- SQL 中任务成功摘要和所有发现一起提交；中途失败全部回滚。故障/取消/未完成任务没有有效评分。
- 进程崩溃、同步请求中断或超时后，未完成任务在期限后的下次查询时标记失败。不会自动重放原文；先核对任务历史，再重新提交。数据库不可用时先显示存储错误，恢复后可查询状态。
- 使用 PostgreSQL 时摘要跨实例、跨重启保存；显式离线内存模式仅保留到进程结束。

## English

Open **Risk findings → Content scans**, name the task, choose a content type and paste the text. Leave security domains empty for automatic selection. Personal users may leave the asset empty; enterprise users should select their organization and associate a registered asset by name.

Task history refreshes every 3 seconds. Expand a completed task and open its findings to review evidence and remediation before updating finding states. A scan evaluates only submitted content; it neither executes commands nor contacts the asset. Its score does not replace the overall asset risk score, and zero matches do not prove safety.

Task access requires scans:read, execution/cancellation requires scans:execute, and asset association also requires assets:read. Foreign or missing assets return 404. Original submitted text is not kept in task rows, but findings may contain matched evidence. Secondary model judgements explicitly identify actual Mock use.

Secondary judgement additionally requires models:write. Configure an endpoint and default route in Model Gateway for the selected organization. Live calls share gateway containment, policies, content filters, classification, quotas and metering. A higher asset classification cannot be lowered by the form. AGF_MOCK_MODE=1 uses the explicitly labelled offline rule-based-judge without external requests.

Expanded tasks show completed judgement counts and explicit degradation. Missing endpoints, policy/classification/quota blocks, timeouts or invalid JSON/evidence references retain rule results and increment the failure count; they do not create a model verdict. The overall 120-second deadline still applies. Cancelling cannot undo upstream usage already incurred.

Security judgements bypass response caches to request a current assessment each time. Resubmitting identical content can incur model usage. Historical tasks are not retroactively given new model judgements.

For batch integration, use the JSON example above with POST /api/v1/scans, wait=false, and your organization's authentication/tenant headers. Poll the returned task_id, inspect terminal and job.state, then follow finding_ids. Each request allows 1–100 targets, 1 MiB per text, 4 MiB total, names up to 200 UTF-8 bytes and up to five domains.

Execution expires 120 seconds after task creation. Cancellation and completion serialize: the first committed terminal state wins. SQL commits all findings and the successful summary atomically; failed/cancelled/incomplete tasks have no valid score. Interrupted tasks are marked failed on the next read after expiry. Database outages surface as errors; check history after recovery before resubmitting. Inputs are not automatically replayed. PostgreSQL history survives restart and supports multiple instances; offline memory does not.
