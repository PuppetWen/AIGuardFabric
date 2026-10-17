# 红队战役与 CI 指南 / Red-team campaigns and CI

控制台提供 **本地确定性模拟**、**真实 Agent HTTP** 和 **真实 MCP HTTP 只读哨兵检测** 三种模式。模拟不连接台账资产，不证明真实资产安全。Agent 接入见 [真实 Agent 指南](agent-redteam-guide.md)，MCP 接入见 [MCP 只读哨兵指南](mcp-redteam-guide.md)。MCP 已支持固定单次查询与同一只读工具的两步资料查询；跨工具链、旧版 SSE 和多 Agent 执行适配器仍在开发。

## 个人用户

1. 登录后确认顶部组织，打开红队中心。
2. 点击「发起红队战役」并选「本地模拟」，填写名称、类别、模拟目标名称和用例上限（1–500）。全部 12 类均使用后端原始类别。
3. 防护强度 0 模拟无防护，100 模拟完全拦截；这是输入参数，不是测得的安全分数。
4. 开启 CI 门禁并选择严重等级。成功攻击达到此等级及以上时不通过；任务「已完成」与 CI「通过」不同。
5. 提交返回任务 ID，页面每 3 秒刷新。关闭页面不取消任务；详情提供取消入口。任务最多执行 10 分钟，服务中断后到期标记失败。
6. 展开逐用例证据，查看保存的输入、模拟信号与执行设置。下载报告 Markdown 和完整证据 JSON。真实 Agent 模式最多选择 20 个可判定用例；MCP 当前仅支持固定 `RT-MCP-001/002/003`，接入前按专用指南配置哨兵和跨工具用例所需的详情工具。

模拟结果不创建已确认的风险发现，不改变真实资产风险，不计入总览真实红队成功率。没有执行记录时成功率未知。

真实 Agent/MCP 的已判定命中与战役完成结果一起提交为待审发现和告警；同一战役、资产及风险域的命中聚合到一条告警。战役详情可打开关联发现，也可按战役编号查看告警，再从告警详情进入发现与案件。只有管理员预先启用匹配的[自动响应模板](automatic-response-guide.md)，新告警才会自动建案；默认“只建待研判案件”模板没有处置动作。未启用时可在发现详情人工确认建案。模拟、无法判定及执行失败不创建发现或告警。

逐用例评估状态分为“已判定”“无法判定”和“执行失败”。缺少用例要求的工具或能力、目标响应缺少必要证据时记为无法判定；调用异常记为执行失败。只有完成用例声明的检查后才纳入已判定成功率。未观测到成功信号仅表示该检查没有发现信号，不能宣称目标全面安全。启用 CI 时，存在任何未判定用例均不能放行；复测也不会将其计为已修复。

## 企业权限与复测

- 测试人员需要 `redteam:read`、`redteam:execute`；真实 Agent 另需 `agents:read`、配置需 `agents:write`；真实 MCP 另需 `mcps:read`、配置需 `mcps:write`。只读审核人员只需 `redteam:read` 查看战役。租户由当前会话或 `X-AGF-Tenant` 指定。
- PostgreSQL 模式在接受任务前提交输入，在完成时一次提交结果及报告。内存模式仅在当前进程中保留。
- 「复测原用例」创建新任务，沿用原战役保存的用例版本与 CI 门槛，原结果不修改。模拟战役可调整名称及模拟防护参数；真实 Agent/MCP 战役须有当前目标配置版本、同一有效资产及对应的读权限，复测会再次发送真实请求。目标停用、删除、移至其他资产或版本过期均拒绝。
- 对完整基线，报告列出本次未再成功、仍成功和新增成功的用例键。未完成基线不生成改善结论。模拟参数变好不能作为真实系统已修复的结论。
- 保存版本之前的历史记录标记模式未知，不推测真实/模拟来源，也不支持凭空补造原用例复测。
- 取消与完成使用同一个行锁；已经完成的任务不会被晚到的取消改写，取消先提交则后续执行不能发布结果。重复完成不会追加第二份证据。

## CI 接入

在项目中使用 `scripts/redteam-ci.ps1`。通过 CI 密钥管理把只具备相应租户红队读/执行权限的 API Key 注入 `AGF_CI_API_KEY`，不要写进仓库或命令参数。

```powershell
# CI secret store supplies AGF_CI_API_KEY.
.\scripts\redteam-ci.ps1 -BaseUrl 'http://localhost:8080' `
  -TenantId '<tenant UUID>' -Name 'CI simulation' `
  -SeverityThreshold high -GuardStrength 100 -MaxCases 200 -AllowSimulation
exit $LASTEXITCODE
```

也可传入 `-CampaignId '<UUID>'` 校验已有战役。真实 Agent 传 `-AgentTargetId '<UUID>' -CaseKeys 'RT-DI-031','RT-MT-021'`，分别检查单轮和保留会话历史的三轮哨兵泄露；真实 MCP 传 `-McpTargetId '<UUID>' -CaseKeys 'RT-MCP-001','RT-MCP-002','RT-MCP-003'`，分别检查单次、同工具两步和跨两个已配置只读工具的两步资料查询。两者均不需 `-AllowSimulation`。未显式允许模拟时拒绝模拟报告。默认把 Markdown 和 JSON 保存到项目 `artifacts/redteam/<任务ID>/`，可用 `-OutputDirectory` 指定 CI 工件目录。

退出码：`0` 门禁通过且所有用例均已判定，`1` 达到门槛的攻击成功，`2` 用例未全部判定、执行失败、取消、未知模式、门禁停用、报告缺失、超时或接口错误。脚本先保存报告和证据，再检查评估覆盖率。CI 不得仅依据 HTTP 200 或任务 completed 放行。

API：`POST /api/v1/redteam/campaigns` 返回 **202 + task_id**；`GET /{id}` 查询任务，`GET /{id}/results` 查看摘要，`GET /{id}/report` 读取报告，`GET /{id}/evidence` 下载固定输入及证据，`POST /{id}/cancel` 取消，`POST /{id}/retest` 复测。后续路径均接在 `/api/v1/redteam/campaigns` 后。

```json
{"name":"CI simulation","execution_mode":"simulator","categories":["direct-injection","tool-abuse"],"max_cases":200,"guard_strength":30,"ci_gate":true,"severity_threshold":"high"}
```

未知类别、用例键、额外字段、非法门槛或无匹配用例返回 400；不会静默忽略资产列表或模拟不支持的目标设置。

## 定时巡航与重试

定时巡航接入和排错见 [调度指南](scheduler-guide.md)。API 可携带 `Idempotency-Key`（1–200 个可见 ASCII 字符）；同租户同调用身份的相同参数返回原任务，不重新读取用例版本，不重复执行。改变参数返回 409。`scheduled=true` 加 `partition:{index,total}` 用于调度，序号从 0 开始、总数 1–256；空片返回 200 和 `skipped=true`。非空任务仍返回 202。计划任务超过每片上限时拒绝，不截断。

## English

The console offers a **local deterministic simulator**, a **real Agent HTTP target**, and a **real MCP HTTP read-only canary probe**. Simulation never contacts inventory assets or contributes to live attack metrics. Follow the [Agent target guide](agent-redteam-guide.md) or [MCP target guide](mcp-redteam-guide.md). MCP supports one fixed query or two queries through the same audited read-only tool; cross-tool workflows, legacy SSE and multi-Agent execution remain separate work.

An evaluated real Agent/MCP hit commits a pending finding and alert with the campaign. Campaign details link to findings and allow searching linked alerts; alert details link to any case. A matching automation enabled before the new alert can create a case. The default case-for-triage template performs no response action; otherwise an operator may confirm a manual case from the finding. Simulation, inconclusive results and execution errors create neither finding nor alert.

Each case is evaluated, inconclusive, or an execution error. Missing tools or capabilities and insufficient response evidence are inconclusive; target call errors are execution errors. Only cases with every declared check executed enter the evaluated success rate. Absence of a success signal proves only that the check did not observe it. An enabled CI gate requires complete assessment coverage, and retests never count unassessed cases as resolved.

Choose categories, a case limit (1–500), a guard parameter (0–100) and a CI severity threshold. Submit, inspect the persisted task and expand per-case evidence. Download Markdown and JSON. Closing the browser does not cancel a run. PostgreSQL is required for restart persistence. Runs expire after 10 minutes; cancellation and completion are serialized.

Readers need `redteam:read`; operators additionally need `redteam:execute`. Real Agent work requires `agents:read` (and `agents:write` to configure); real MCP requires `mcps:read` (and `mcps:write` to configure). Retests reuse saved case versions and the CI threshold. Simulator retests can change the guard parameter; real target retests require the current target revision and the same active asset, then send real requests. Compare completed baselines only. Improved simulator results do not establish real remediation.

Use `scripts/redteam-ci.ps1` with a secret-injected `AGF_CI_API_KEY`, `-BaseUrl`, `-TenantId` and explicit `-AllowSimulation` for simulation, `-AgentTargetId` and `-CaseKeys` for real Agent, or `-McpTargetId` and `-CaseKeys RT-MCP-001,RT-MCP-002,RT-MCP-003` for MCP. RT-MCP-003 requires a configured second read-only tool. Exit codes are 0 (gate passed), 1 (gate failed), and 2 (execution/API/incomplete or invalid evidence). Missing or disabled gates never pass. Store the generated evidence directory as a CI artifact.

For periodic runs, follow the [scheduler guide](scheduler-guide.md). API callers may send `Idempotency-Key` to safely retry a lost acknowledgement; reuse is scoped to tenant and caller, and changed parameters return 409. Scheduled partitions explicitly skip when empty and reject oversized selections.
