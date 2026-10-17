import { Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

export function RedteamGuide() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  return <Space direction="vertical">
    <Typography.Paragraph>{zh
      ? '结果口径：缺少工具、能力或判定证据为“无法判定”，调用异常为“执行失败”。这两类不计入已判定成功率，已启用的 CI 不能放行；复测也不会把它们算作已修复。展开用例查看具体原因。没有成功信号仅表示本次检查未观测到该信号。'
      : 'Missing tools, capabilities or evidence are inconclusive; call errors are execution failures. These are excluded from the evaluated success rate and prevent an enabled CI gate from passing. Retests do not count them as resolved. Expand a case for the reason. No success signal means only that the declared signal was not observed.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh
      ? '个人：发起模拟战役，选择类别、用例上限和 CI 等级。0 表示模拟无防护，100 表示模拟全部拦截。提交后查看任务 ID、逐用例信号与证据，可下载 Markdown 和 JSON。模拟不会访问设备或创建真实风险发现。'
      : 'Personal use: launch a simulator campaign, choose categories, a case limit and a CI threshold. A guard strength of 0 simulates no protection; 100 simulates full blocking. Inspect signals and evidence; download Markdown and JSON. Simulation does not contact devices or create confirmed findings.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh
      ? '真实 Agent：先在 Agent 管理页纳管资产；在被测 Agent 的系统提示词内设置专用哨兵；展开本页“Agent 目标配置”，选择资产并填写服务端可达的 OpenAI Chat Completions 兼容 URL、模型和可选 Bearer 令牌，再填写相同哨兵。发起战役时选择“真实 Agent HTTP”、已启用目标和可判定用例：RT-DI-031 为单轮检查，RT-MT-021 连续发送三轮并保留会话历史。版本不匹配或目标停用会拒绝发起；令牌、哨兵不会出现在报告中。'
      : 'Real Agent: register the asset in Agent Management; put a dedicated canary in the target Agent system prompt; open Agent target configuration here and select the asset. Enter a server-reachable OpenAI Chat Completions-compatible URL, model and optional Bearer token, then the same canary. Launch a Real Agent HTTP campaign with RT-DI-031 for one turn or RT-MT-021 for three turns with conversation history. Changed or disabled profiles are rejected; token and canary never appear in reports.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh
      ? '真实 MCP：先在 MCP 管理页纳管 Server；在上游私有数据中放入专用哨兵，人工审计查询工具确实只读且声明 readOnlyHint。配置可达的 2026-07-28 Streamable HTTP URL、工具名、字符串参数名和相同哨兵。RT-MCP-001 单次查询；RT-MCP-002 用同一工具完成两步；RT-MCP-003 须额外配置不同的只读详情工具和参数，再把首轮资料标识交给它。每次调用前重新检查工具声明，首轮必须只返回不超过 256 字节的单行标识。响应原文和哨兵不会进入证据包。'
      : 'Real MCP: register the Server, place a dedicated canary in private upstream data, and audit the query tool as read-only with readOnlyHint. Configure its reachable 2026-07-28 Streamable HTTP URL, tool and string argument. RT-MCP-001 is one query; RT-MCP-002 makes two calls to the same tool; RT-MCP-003 needs a distinct read-only detail tool and argument. Each call rechecks the tool declaration. The first result must be one reference of at most 256 bytes. Raw responses and the canary are omitted from evidence.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh
      ? 'MCP 工具用量：展开“MCP 目标配置”，在目标行点“用量”，再点“刷新用量”查看该配置的累计直接调用。只读查看角色也可使用。列举工具不计数，两步用例分别记录两次工具调用；“收到结果”、失败、未知和进行中分列。连接中断后没有确认结果记为未知；数量不是 CI 结论、业务成功率或账单。MCP 管理中的代理端点用量单独查看。'
      : 'MCP tool usage: open MCP target configuration, choose Usage on the target row, then Refresh usage to inspect cumulative direct calls for that profile. Read-only viewers can use it too. Discovery is excluded; a two-step case records two calls separately. Result received, failed, unknown and in-flight calls have separate columns. An unconfirmed result after disconnection is unknown. Counts are not CI conclusions, business success rates or bills. Proxy endpoint usage is separate in MCP Management.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh
      ? '真实 Agent 或 MCP 用例经判定命中后，完成战役时会原子写入关联的待审风险发现与告警；同一战役、资产和风险域的命中聚合为一条告警。战役详情可直达发现和关联告警；告警详情可查看发现及案件。模拟、无法判定和执行失败不会生成发现或告警。若提前启用匹配的“只建待研判案件”自动响应，新告警可建案但不会执行处置；否则可在发现详情人工确认建案。'
      : 'An evaluated real Agent or MCP hit atomically creates a linked pending finding and alert. Hits in the same campaign, asset and domain share one alert. Campaign details link to findings and alerts, and the alert links to any case. Simulation, inconclusive results and execution errors create neither. Enable a matching case-for-triage automation before the run to open a case without a response action, or confirm a manual case from the finding.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh
      ? '企业：Agent 测试另需 agents:read，配置需 agents:write；MCP 测试另需 mcps:read，配置需 mcps:write。所有战役需 redteam:read/execute。可由管理员负责配置，执行人员仅选择已启用目标。历史按顶部组织隔离；复测核对同一资产与当前目标版本，并再次发送真实请求。未判定和执行失败不能算通过。'
      : 'Enterprise use: Agent testing also needs agents:read and configuration needs agents:write; MCP testing needs mcps:read and configuration needs mcps:write. Campaigns need redteam:read/execute. An administrator can configure targets while operators select enabled profiles. History is tenant-scoped. Retests verify the same asset and current profile revision before sending real requests. Inconclusive or failed checks cannot pass.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh
      ? 'CI：使用 scripts/redteam-ci.ps1，并通过 AGF_CI_API_KEY 环境变量提供密钥。真实 Agent 传 -AgentTargetId 与 -CaseKeys；MCP 传 -McpTargetId 和 -CaseKeys RT-MCP-001,RT-MCP-002,RT-MCP-003（最后一条需详情工具）。模拟需显式传 -AllowSimulation。门禁失败返回 1，执行/接口异常返回 2。'
      : 'CI: use scripts/redteam-ci.ps1 with AGF_CI_API_KEY. Pass -AgentTargetId and -CaseKeys for Agent, or -McpTargetId with -CaseKeys RT-MCP-001,RT-MCP-002,RT-MCP-003 for MCP (the last needs a detail tool). Simulation requires -AllowSimulation. Failed gates exit 1; execution/API errors exit 2.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh
      ? '定时巡航：部署 agf-scheduler，配置 AGF_SERVER_URL、AGF_SCHEDULER_TENANT_ID 和具有 redteam:read/execute 的服务 API Key。每周一 03:00 UTC 默认运行；AGF_SCHEDULER_REDTEAM_CRUISE_CRON 可修改时间，AGF_SCHEDULER_REDTEAM_GUARD 控制模拟强度。任务名以 scheduler-cruise 开头，可在此查看证据；调度端同时保存 JSON 和 Markdown。巡航未启用 CI，执行成功不代表安全通过。'
      : 'Scheduled cruises: deploy agf-scheduler with AGF_SERVER_URL, AGF_SCHEDULER_TENANT_ID and a service API key with redteam:read/execute. The default is Monday 03:00 UTC; set AGF_SCHEDULER_REDTEAM_CRUISE_CRON to change it and AGF_SCHEDULER_REDTEAM_GUARD for simulator strength. Find scheduler-cruise tasks here; JSON and Markdown are also archived by the scheduler. Cruises do not enable CI, so execution success is not a security pass.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh
      ? '模拟任务最多 500 个用例，真实 Agent 最多 20 个，MCP 当前只支持 RT-MCP-001/002/003；均限时 10 分钟。取消后不发布新结果，但正在进行的请求可能结束。配置 PostgreSQL 才能跨重启保留。跨服务或任意工具链和多 Agent 用例尚未开放；模拟报告不能用作生产安全验收。'
      : 'Simulator runs allow up to 500 cases, real Agent up to 20, and MCP only RT-MCP-001/002/003; all expire after 10 minutes. Cancellation publishes no new result, though an in-flight request may finish. PostgreSQL preserves runs across restarts. Arbitrary or cross-server tool chains and multi-Agent cases remain unavailable. Simulator reports are not production security acceptance.'}</Typography.Paragraph>
    <Link to="/redteam">{zh ? '打开红队中心' : 'Open red-team center'}</Link>
  </Space>;
}
