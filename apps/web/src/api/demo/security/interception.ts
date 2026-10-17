import type {
  InterceptEvent,
  InterceptPoint,
  InterceptPointStatus,
  PolicyAction,
} from '@/types/domain';

import { agoSeconds, seeded } from '../../../utils/time';

/* ------------------------------------------------------------------ */
/* Runtime interception                                                */
/* ------------------------------------------------------------------ */

export const demoInterceptPoints: InterceptPointStatus[] = [
  {
    point: 'mcp-proxy',
    enabled: true,
    mode: 'enforce',
    health: 'healthy',
    throughputPerMin: 8_420,
    blocked24h: 522,
    p95LatencyMs: 6,
    version: '0.9.4',
    lastError: null,
  },
  {
    point: 'ai-gateway',
    enabled: true,
    mode: 'enforce',
    health: 'healthy',
    throughputPerMin: 12_960,
    blocked24h: 96,
    p95LatencyMs: 11,
    version: '0.9.4',
    lastError: null,
  },
  {
    point: 'process-hook',
    enabled: true,
    mode: 'monitor',
    health: 'degraded',
    throughputPerMin: 340,
    blocked24h: 0,
    p95LatencyMs: 42,
    version: '0.9.2',
    lastError: 'eBPF 探针在 kernel 5.10.134-16 上加载失败，已降级为 ptrace 模式',
  },
  {
    point: 'egress-proxy',
    enabled: true,
    mode: 'enforce',
    health: 'healthy',
    throughputPerMin: 2_180,
    blocked24h: 188,
    p95LatencyMs: 4,
    version: '0.9.4',
    lastError: null,
  },
];

const INTERCEPT_SCENARIOS: { reason: string; policyName: string; action: PolicyAction; severity: InterceptEvent['severity'] }[] = [
  {
    reason: '目标域名不在 Skill 白名单内',
    policyName: '出网域名黑名单阻断',
    action: 'deny',
    severity: 'high',
  },
  { reason: '工具参数命中明文凭据特征', policyName: '明文凭据出站拦截', action: 'deny', severity: 'critical' },
  { reason: '工具具备 execute 能力且无审批', policyName: '高危工具二次确认', action: 'quarantine', severity: 'critical' },
  { reason: '返回字段包含手机号', policyName: '个人信息出参脱敏', action: 'mask', severity: 'medium' },
  { reason: '越狱分类器得分 0.81', policyName: '越狱命中后转安全模型', action: 'redirect', severity: 'high' },
  { reason: '影子 MCP 调用（未登记）', policyName: '影子 MCP 调用告警', action: 'alert', severity: 'medium' },
  { reason: '租户 Token 用量达到 87%', policyName: '租户 Token 配额限流', action: 'throttle', severity: 'low' },
  { reason: '涉密会话请求外部模型端点', policyName: '涉密会话本地模型强制', action: 'redirect', severity: 'high' },
  { reason: '单次返回行数超过 10,000 行', policyName: '出网域名黑名单阻断', action: 'deny', severity: 'medium' },
  { reason: '命令黑名单命中 rm -rf /', policyName: '出网域名黑名单阻断', action: 'deny', severity: 'critical' },
];

const INTERCEPT_AGENTS = [
  '客服智能助手 Copilot',
  '风控决策 Agent',
  '营销文案生成 Agent',
  '数据清洗 ETL Agent',
  '投研摘要 Agent',
  '运维告警分析 Agent',
];

const INTERCEPT_TARGETS = [
  { mcpName: 'order-mcp', toolName: 'refund_order' },
  { mcpName: 'postgres-mcp', toolName: 'execute_query' },
  { mcpName: 'shell-mcp', toolName: 'run_command' },
  { mcpName: 'clickhouse-mcp', toolName: 'ch_export' },
  { mcpName: 'browser-use-mcp', toolName: 'fill_form' },
  { mcpName: 'fs-mcp', toolName: 'write_file' },
  { mcpName: null, toolName: null },
];

export const demoInterceptEvents: InterceptEvent[] = (() => {
  const rand = seeded(31337);
  const events: InterceptEvent[] = [];
  for (let i = 0; i < 48; i += 1) {
    const scenario = INTERCEPT_SCENARIOS[i % INTERCEPT_SCENARIOS.length] as (typeof INTERCEPT_SCENARIOS)[number];
    const target = INTERCEPT_TARGETS[i % INTERCEPT_TARGETS.length] as (typeof INTERCEPT_TARGETS)[number];
    const point = (['mcp-proxy', 'ai-gateway', 'egress-proxy', 'process-hook'] as InterceptPoint[])[i % 4] as InterceptPoint;
    events.push({
      id: `itc-${String(i + 1).padStart(4, '0')}`,
      ts: agoSeconds(Math.round(i * 7.5 + rand() * 4)),
      point,
      agentName: INTERCEPT_AGENTS[i % INTERCEPT_AGENTS.length] as string,
      mcpName: target.mcpName,
      toolName: target.toolName,
      action: scenario.action,
      policyName: scenario.policyName,
      reason: scenario.reason,
      payloadDigest: `sha256:${(0xa1b2c3d4 + i * 7919).toString(16).padStart(8, '0')}${(i * 2654435761)
        .toString(16)
        .slice(-8)}`,
      latencyMs: Math.round((2 + rand() * 18) * 10) / 10,
      severity: scenario.severity,
    });
  }
  return events;
})();
