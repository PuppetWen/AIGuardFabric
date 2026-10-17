import type {
  ModelEndpoint,
  ModelRoutePolicy,
  ModelUsageAggregate,
  TokenUsageRecord,
} from '@/types/domain';

import { agoHours, dailySeries, seeded } from '../../utils/time';

/* ------------------------------------------------------------------ */
/* Model endpoints                                                     */
/* ------------------------------------------------------------------ */

export const demoModelEndpoints: ModelEndpoint[] = [
  {
    id: 'ep-qwen-max',
    vendor: 'qwen',
    model: 'qwen-max-2025-01-25',
    endpoint: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    local: false,
    mockMode: false,
    inputPricePerKTok: 0.02,
    outputPricePerKTok: 0.06,
    priority: 10,
    fallback: false,
    latencyP95Ms: 1_180,
    health: 'healthy',
  },
  {
    id: 'ep-qwen-plus',
    vendor: 'qwen',
    model: 'qwen-plus-latest',
    endpoint: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    local: false,
    mockMode: false,
    inputPricePerKTok: 0.004,
    outputPricePerKTok: 0.012,
    priority: 20,
    fallback: true,
    latencyP95Ms: 860,
    health: 'healthy',
  },
  {
    id: 'ep-gpt-4o',
    vendor: 'openai',
    model: 'gpt-4o-2024-11-20',
    endpoint: 'https://api.openai.com/v1',
    local: false,
    mockMode: false,
    inputPricePerKTok: 0.018,
    outputPricePerKTok: 0.072,
    priority: 30,
    fallback: true,
    latencyP95Ms: 1_460,
    health: 'healthy',
  },
  {
    id: 'ep-claude',
    vendor: 'anthropic',
    model: 'claude-sonnet-4-20250514',
    endpoint: 'https://api.anthropic.com/v1',
    local: false,
    mockMode: true,
    inputPricePerKTok: 0.021,
    outputPricePerKTok: 0.105,
    priority: 40,
    fallback: true,
    latencyP95Ms: 1_720,
    health: 'degraded',
  },
  {
    id: 'ep-deepseek',
    vendor: 'deepseek',
    model: 'deepseek-chat',
    endpoint: 'https://api.deepseek.com/v1',
    local: false,
    mockMode: false,
    inputPricePerKTok: 0.002,
    outputPricePerKTok: 0.008,
    priority: 25,
    fallback: true,
    latencyP95Ms: 940,
    health: 'healthy',
  },
  {
    id: 'ep-vllm-local',
    vendor: 'vllm',
    model: 'Qwen2.5-72B-Instruct',
    endpoint: 'http://vllm.intra.acme:8000/v1',
    local: true,
    mockMode: false,
    inputPricePerKTok: 0,
    outputPricePerKTok: 0,
    priority: 50,
    fallback: true,
    latencyP95Ms: 1_980,
    health: 'degraded',
  },
  {
    id: 'ep-ollama-local',
    vendor: 'ollama',
    model: 'llama3.1:70b',
    endpoint: 'http://ollama.intra.acme:11434/v1',
    local: true,
    mockMode: false,
    inputPricePerKTok: 0,
    outputPricePerKTok: 0,
    priority: 60,
    fallback: true,
    latencyP95Ms: 2_640,
    health: 'healthy',
  },
  {
    id: 'ep-zhipu',
    vendor: 'zhipu',
    model: 'glm-4-plus',
    endpoint: 'https://open.bigmodel.cn/api/paas/v4',
    local: false,
    mockMode: true,
    inputPricePerKTok: 0.007,
    outputPricePerKTok: 0.007,
    priority: 70,
    fallback: true,
    latencyP95Ms: 1_320,
    health: 'unknown',
  },
  {
    id: 'ep-moonshot',
    vendor: 'moonshot',
    model: 'moonshot-v1-128k',
    endpoint: 'https://api.moonshot.cn/v1',
    local: false,
    mockMode: false,
    inputPricePerKTok: 0.0084,
    outputPricePerKTok: 0.0084,
    priority: 80,
    fallback: true,
    latencyP95Ms: 1_540,
    health: 'healthy',
  },
  {
    id: 'ep-azure-gpt4o-mini',
    vendor: 'azure-openai',
    model: 'gpt-4o-mini',
    endpoint: 'https://acme-ai.openai.azure.com/',
    local: false,
    mockMode: false,
    inputPricePerKTok: 0.0011,
    outputPricePerKTok: 0.0044,
    priority: 15,
    fallback: false,
    latencyP95Ms: 700,
    health: 'healthy',
  },
];

/* ------------------------------------------------------------------ */
/* Routing policies                                                    */
/* ------------------------------------------------------------------ */

export const demoRoutePolicies: ModelRoutePolicy[] = [
  {
    id: 'rt-prod-default',
    version: 0,
    name: '生产默认路由',
    primaryEndpointId: 'ep-qwen-max',
    fallbackEndpointIds: ['ep-qwen-plus', 'ep-deepseek', 'ep-vllm-local'],
    strategy: 'priority',
    weights: { 'ep-qwen-max': 70, 'ep-qwen-plus': 30 },
    budgetCnyPerDay: 1_200,
    enabled: true,
  },
  {
    id: 'rt-cost-first-batch',
    version: 0,
    name: '批处理成本优先',
    primaryEndpointId: 'ep-deepseek',
    fallbackEndpointIds: ['ep-qwen-plus', 'ep-azure-gpt4o-mini'],
    strategy: 'cost-first',
    weights: { 'ep-deepseek': 80, 'ep-qwen-plus': 20 },
    budgetCnyPerDay: 300,
    enabled: true,
  },
  {
    id: 'rt-local-sensitive',
    version: 0,
    name: '涉密数据本地优先',
    primaryEndpointId: 'ep-vllm-local',
    fallbackEndpointIds: ['ep-ollama-local'],
    strategy: 'priority',
    weights: { 'ep-vllm-local': 100 },
    budgetCnyPerDay: 0,
    enabled: true,
  },
  {
    id: 'rt-latency-chat',
    version: 0,
    name: '实时会话时延优先',
    primaryEndpointId: 'ep-azure-gpt4o-mini',
    fallbackEndpointIds: ['ep-qwen-plus', 'ep-deepseek'],
    strategy: 'latency-first',
    weights: { 'ep-azure-gpt4o-mini': 60, 'ep-qwen-plus': 40 },
    budgetCnyPerDay: 450,
    enabled: false,
  },
];

/* ------------------------------------------------------------------ */
/* Token usage                                                         */
/* ------------------------------------------------------------------ */

/** Daily token totals for the last 30 days (input + output). */
export const demoTokenTrend = dailySeries(30, 28_400_000, 6_200_000, 4242, 3_600_000);

const usageAgents: { id: string; name: string }[] = [
  { id: 'agt-copilot', name: '客服智能助手 Copilot' },
  { id: 'agt-risk', name: '风控决策 Agent' },
  { id: 'agt-langchain-etl', name: '数据清洗 ETL Agent' },
  { id: 'agt-codereview', name: '代码评审助手' },
  { id: 'agt-coze-bot', name: '内部知识问答 Bot' },
  { id: 'agt-qwen-agent', name: '投研摘要 Agent' },
  { id: 'agt-marketing', name: '营销文案生成 Agent' },
  { id: 'agt-crewai-audit', name: '合规审计助手' },
];

export const demoTenantUsageRecords: TokenUsageRecord[] = (() => {
  const rand = seeded(90210);
  const records: TokenUsageRecord[] = [];
  for (let i = 0; i < 60; i += 1) {
    const agent = usageAgents[i % usageAgents.length] as { id: string; name: string };
    const endpoint = demoModelEndpoints[i % 6] as ModelEndpoint;
    const inputTokens = Math.round(180_000 + rand() * 2_600_000);
    const outputTokens = Math.round(40_000 + rand() * 620_000);
    const costCny =
      (inputTokens / 1000) * (endpoint.inputPricePerKTok ?? 0) +
      (outputTokens / 1000) * (endpoint.outputPricePerKTok ?? 0);
    records.push({
      id: `usg-${String(i + 1).padStart(4, '0')}`,
      ts: agoHours(i * 1.5 + rand()),
      tenantId: 'ten-acme',
      agentId: agent.id,
      agentName: agent.name,
      endpointId: endpoint.id,
      model: endpoint.model,
      inputTokens,
      outputTokens,
      costCny: Math.round(costCny * 100) / 100,
      currency: 'CNY' as const, mocked: true, cacheHit: false,
    });
  }
  return records;
})();

export const demoModelUsage: ModelUsageAggregate[] = (() => {
  const rand = seeded(5150);
  return demoModelEndpoints.map((endpoint, index) => {
    const calls = Math.round(1_200 + rand() * 88_000);
    const inputTokens = Math.round(calls * (900 + rand() * 2_400));
    const outputTokens = Math.round(calls * (180 + rand() * 520));
    const costCny =
      (inputTokens / 1000) * (endpoint.inputPricePerKTok ?? 0) +
      (outputTokens / 1000) * (endpoint.outputPricePerKTok ?? 0);
    return {
      endpointId: endpoint.id,
      model: endpoint.model,
      vendor: endpoint.vendor,
      inputTokens,
      outputTokens,
      costCny: Math.round(costCny * 100) / 100,
      currency: 'CNY' as const, mocked: true, cacheHit: false,
      calls: calls + index * 37,
    };
  });
})();

export const demoTokenSpendTodayCny = Math.round(
  demoModelUsage.reduce((sum, item) => sum + item.costCny, 0) * 100,
) / 100;

/* ------------------------------------------------------------------ */
/* Skills registry & onboarding plans (split out, re-exported here)    */
/* ------------------------------------------------------------------ */

export { demoSkills } from './models/skills';
export { buildOnboardingPlan } from './models/onboarding';
