import type { CallbackKind } from './callbackPlan';

export interface SchedulerTask {
  kind: CallbackKind;
  runtimeName: string;
  title: [string, string];
  target: [string, string];
  setup: [string, string];
  evidence: [string, string];
  dependencies: CallbackKind[];
}

export const SCHEDULER_TASKS: SchedulerTask[] = [
  {
    kind: 'asset-inventory', runtimeName: 'asset-inventory', title: ['资产台账统计 / 可选 AgentTeams 盘点', 'Asset statistics / optional AgentTeams inventory'],
    target: ['默认统计已有资产，不发现新资源。可明确启用 AgentTeams 完整同步。',
      'The default reports existing assets. It discovers no new resources; AgentTeams sync is an explicit option.'],
    setup: ['云绑定需要 alicloud:read 与 assets:read；资产汇总配置单分片 total=1。自动 AgentTeams 另需 alicloud:write、assets:write，先启用连接并手动同步；部署设置 AGF_SCHEDULER_AGENTTEAMS_SYNC_ENABLED=true，真实连接还需 AGF_SCHEDULER_AGENTTEAMS_CONFIRM_LIVE=true。',
      'Cloud bindings need alicloud:read and assets:read; use one summary partition (total=1). AgentTeams additionally needs alicloud:write and assets:write, an enabled connection and a manual sync first. Set AGF_SCHEDULER_AGENTTEAMS_SYNC_ENABLED=true; live sync also requires AGF_SCHEDULER_AGENTTEAMS_CONFIRM_LIVE=true.'],
    evidence: ['统计 JSON；如启用同步，再核对同步回执和资产台账。', 'Statistics JSON; if sync is enabled, inspect its receipt and inventory.'],
    dependencies: [],
  },
  {
    kind: 'log-pull', runtimeName: 'log-pull', title: ['到期 HTTP Pull 日志源', 'Due HTTP Pull log sources'],
    target: ['处理本租户所有启用且到期的 HTTP Pull 源，使用平台持久游标和解析器。',
      'Processes all enabled, due HTTP Pull sources in this tenant using durable platform cursors and parsers.'],
    setup: ['sources:read、sources:write。先在接入管理配置并启用源；此处不能选择源 ID，也不把源凭据传给云任务。',
      'sources:read and sources:write. Configure and enable sources in Integrations first. This form cannot select source IDs or pass source credentials to cloud jobs.'],
    evidence: ['实际 accepted/skipped/failed 及日志查询；没有到期源时可跳过。', 'Actual accepted/skipped/failed counts and log queries; no due sources may mean skipped work.'],
    dependencies: ['asset-inventory'],
  },
  {
    kind: 'redteam-cruise', runtimeName: 'redteam-cruise', title: ['离线模拟红队用例', 'Offline simulated red-team cases'],
    target: ['平台当前用例库和固定 scheduler-local-simulator 目标；当前不执行真实目标攻击或 CI gate。',
      'Uses platform cases with the fixed scheduler-local-simulator target; it does not run live attacks or a CI gate.'],
    setup: ['redteam:read、redteam:execute。部署模拟强度 AGF_SCHEDULER_REDTEAM_GUARD=0–100，红队目录须可写。',
      'redteam:read and redteam:execute. Deploy AGF_SCHEDULER_REDTEAM_GUARD=0–100 and a writable red-team directory.'],
    evidence: ['平台 campaign ID、用例证据、JSON 和 Markdown 两份产物。', 'Platform campaign ID, case evidence, and both JSON and Markdown artifacts.'],
    dependencies: ['asset-inventory'],
  },
  {
    kind: 'rule-hot-reload', runtimeName: 'rule-hot-reload', title: ['平台策略重载', 'Platform policy reload'],
    target: ['严格检查部署规则目录，再请求平台重载已保存的策略；不上传本地规则正文，不发布到 MSE/APIG。',
      'Strictly checks the deployed rules directory, then asks the platform to reload saved policies; no local rule upload or MSE/APIG publication.'],
    setup: ['云绑定需 alicloud:read、policies:write，单分片 total=1；AGF_RULES_DIR 存在且内容合法，平台 API 可达。',
      'Cloud bindings need alicloud:read and policies:write, with total=1. AGF_RULES_DIR must exist with valid content and the platform API must be reachable.'],
    evidence: ['平台响应 reloaded/total；不能据此证明外部消费者热载。', 'Platform reloaded/total response; this does not prove external consumer loading.'],
    dependencies: [],
  },
  {
    kind: 'report', runtimeName: 'report-generate', title: ['部署目录 Markdown 汇总', 'Deployment Markdown summary'],
    target: ['读取部署规则、红队、统计与归档目录，生成 Markdown。不是控制台 PDF/CSV 或通知计划。',
      'Reads deployment rules, red-team, statistics and archive directories to produce Markdown, not console PDF/CSV or notifications.'],
    setup: ['同租户 API Key 需 alicloud:read、reports:write，单分片 total=1；AGF_RULES_DIR、AGF_REDTEAM_DIR、AGF_REPORT_DIR 和目录权限由部署管理员配置。',
      'A same-tenant API Key needs alicloud:read and reports:write, with total=1. The administrator configures AGF_RULES_DIR, AGF_REDTEAM_DIR, AGF_REPORT_DIR and directory access.'],
    evidence: ['实际 Markdown 文件与摘要。', 'The actual Markdown file and summary.'],
    dependencies: ['asset-inventory', 'log-pull'],
  },
  {
    kind: 'archive', runtimeName: 'cold-archive', title: ['部署报表文件 gzip 归档', 'Deployment report-file gzip archive'],
    target: ['处理 AGF_REPORT_DIR 超龄文件，上传对象存储或明确降级为本地 gzip；不是事件库 Parquet 或云日志清理。',
      'Archives old AGF_REPORT_DIR files to object storage or explicitly degrades to local gzip; not event Parquet or cloud-log deletion.'],
    setup: ['同租户 API Key 需 alicloud:read、reports:write。部署配置对象存储身份/目录、AGF_SCHEDULER_ARCHIVE_AFTER_DAYS；AGF_SCHEDULER_ARCHIVE_DELETE_LOCAL 默认 false。',
      'A same-tenant API Key needs alicloud:read and reports:write. Configure object-storage identity/directories and AGF_SCHEDULER_ARCHIVE_AFTER_DAYS. AGF_SCHEDULER_ARCHIVE_DELETE_LOCAL defaults to false.'],
    evidence: ['文件 SHA256 及 uploaded/local/degraded/failed；降级不显示为云上传成功。',
      'File SHA256 and uploaded/local/degraded/failed; local degradation is not successful cloud upload.'],
    dependencies: ['report'],
  },
];
