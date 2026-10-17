import { findingQuery } from './findingQuery';
import { assetQuery } from './assetQuery';
import type {
  Agent,
  ApiKey,
  Asset,
  AssetFilter,
  AssetProfile,
  BlacklistEntry,
  Campaign,
  CampaignReport,
  CampaignResult,
  DashboardOverview,
  Finding,
  FindingStatus,
  InterceptEvent,
  InterceptPointStatus,
  ListQuery,
  LoginRequest,
  LoginResponse,
  McpServer,
  McpTool,
  ModelEndpoint,
  ModelRoutePolicy,
  ModelUsageAggregate,
  OnboardingMode,
  OnboardingPlan,
  Paged,
  PasswordPolicy,
  Policy,
  QuotaUsage,
  Rule,
  RuleTestResult,
  Skill,
  SkillStatus,
  Tenant,
  TokenUsageRecord,
  TopologyGraph,
  User,
} from '@/types/domain';

import { adaptLoginResponse, type ChangePasswordResponse, type RawLoginResponse } from './contract';
import type { ApiResult } from './dataSource';
import * as demo from './demo';
import { demoLogin } from './demoLogin';
import { paginate, sortBy } from './pagination';
import { callApi } from './transport';
import { policyBody } from './payloads';

/* ------------------------------------------------------------------ */
/* Endpoints                                                           */
/* ------------------------------------------------------------------ */

/**
 * Endpoint surface, part one (dashboard → runtime).
 *
 * Every method returns `ApiResult<T>` so callers can inspect `meta.source` if
 * they need to react to the fallback themselves. The two parts are assembled
 * into the single exported `api` object by `./client`.
 */
export const coreEndpoints = {
  /* --- dashboard --- */
  overview: () => callApi<DashboardOverview>('/api/v1/overview', () => demo.demoDashboard),
  search: (keyword: string, signal?: AbortSignal) =>
    callApi<demo.SearchHit[]>('/api/v1/search', () => demo.searchAll(keyword), {
      query: { q: keyword },
      signal,
      noFallback: true,
    }),

  /* --- identity & tenancy --- */
  // 后端 `LoginBody` 只认 `username`/`password`（`mfa_code`/`device` 可选），
  // 租户由 `X-AGF-Tenant` 头或默认租户决定；响应是 snake_case，需整形后才是 domain 的
  // `LoginResponse`（首登时给 `change_token` 而**不给**会话令牌）。
  login: async (payload: LoginRequest): Promise<ApiResult<LoginResponse>> => {
    const result = await callApi<RawLoginResponse>('/api/v1/auth/login', () => demoLogin(payload), {
      method: 'POST',
      body: { tenant_slug: payload.tenantSlug, username: payload.username, password: payload.password, mfa_code: payload.mfaCode, device: 'agf-console' },
    });
    if (result.meta.source === 'demo') {
      return result as unknown as ApiResult<LoginResponse>;
    }
    return { ...result, data: adaptLoginResponse(result.data, payload) };
  },
  /**
   * 首登改密。
   *
   * 与后端契约对齐：认证用**一次性 change_token 走 `Authorization: Bearer`**（此时会话尚未建立，
   * 所以必须显式传 `token`），请求体是 `{ new_password, current_password? }`。
   */
  changePassword: (payload: {
    token: string;
    currentPassword?: string;
    newPassword: string;
  }) =>
    callApi<ChangePasswordResponse>(
      '/api/v1/auth/change-password',
      () => ({ status: 'ok', mustChangePassword: false }),
      {
        method: 'POST',
        token: payload.token,
        body: {
          new_password: payload.newPassword,
          ...(payload.currentPassword ? { current_password: payload.currentPassword } : {}),
        },
      },
    ),
  tenants: () => callApi<Tenant[]>('/api/v1/tenants', () => demo.demoTenants),
  users: () => callApi<User[]>('/api/v1/users', () => demo.demoUsers),
  apiKeys: () => callApi<ApiKey[]>('/api/v1/api-keys', () => demo.demoApiKeys),
  passwordPolicy: () =>
    callApi<PasswordPolicy>('/api/v1/settings/password-policy', () => demo.demoPasswordPolicy),

  /* --- assets --- */
  assets: (filter: AssetFilter = {}, query: ListQuery = {}) =>
    callApi<Paged<Asset>>(
      '/api/v1/assets',
      () => paginate(sortBy(demo.filterAssets(demo.demoAssets, filter), 'riskScore'), query),
      { query: assetQuery(filter, query) },
    ),
  assetProfile: (id: string) =>
    callApi<AssetProfile>(
      `/api/v1/assets/${id}`,
      () => demo.demoAssetProfiles[id],
      { noFallback: !Object.prototype.hasOwnProperty.call(demo.demoAssetProfiles, id) },
    ),

  /* --- agents --- */
  agents: (query: ListQuery & { sort?: string; flavor?: string; management?: string; observed?: string; transport?: string; shadow?: string; plaintext?: string } = {}) =>
    callApi<Paged<Agent>>('/api/v1/agents', () => paginate(sortBy(demo.demoAgents, 'name', 'asc'), query), {
      query: { ...query }, noFallback: true,
    }),
  onboardingPlan: (agentId: string, mode: OnboardingMode, options: { platform: string; locale: string; publicBase: string }) =>
    callApi<OnboardingPlan>(
      '/api/v1/agents/onboarding-plan',
      () => demo.buildOnboardingPlan(agentId, mode),
      { method: 'POST', body: { agentId, mode, ...options }, noFallback: true },
    ),

  /* --- MCP --- */
  mcps: (query: ListQuery & { sort?: string; flavor?: string; management?: string; observed?: string; transport?: string; shadow?: string; plaintext?: string } = {}) =>
    callApi<Paged<McpServer>>('/api/v1/mcp-servers', () => paginate(sortBy(demo.demoMcpServers, 'riskScore'), query), {
      query: { ...query }, noFallback: true,
    }),
  mcpTools: (serverId: string) =>
    callApi<McpTool[]>(`/api/v1/mcp-servers/${serverId}/tools`, () => demo.toolsForServer(serverId), { noFallback: true }),

  /* --- skills --- */
  skills: (query: ListQuery & { lifecycles?: string } = {}) =>
    callApi<Paged<Skill>>('/api/v1/skills', () => paginate(sortBy(demo.demoSkills, 'requestedAt'), query), {
      query: { ...query }, noFallback: true,
    }),
  updateSkillStatus: (id: string, status: SkillStatus, review: {
    note: string; owner?: string; dataClass?: string; department?: string; expectedUpdatedAt: string;
  }) =>
    callApi<Skill | undefined>(
      `/api/v1/skills/${id}/status`,
      () => demo.demoSkills.find((skill) => skill.id === id),
      { method: 'POST', body: { status, ...review }, noFallback: true },
    ),
  updateSkillWhitelist: (id: string, whitelist: { domains: string[]; paths: string[]; expectedUpdatedAt: string }) =>
    callApi<Skill | undefined>(
      `/api/v1/skills/${id}/whitelist`,
      () => demo.demoSkills.find((skill) => skill.id === id),
      { method: 'PUT', body: whitelist, noFallback: true },
    ),

  /* --- models --- */
  // 注意：`/api/v1/models/endpoints` 与其它列表资源一致返回**分页信封**（`{items,total,page,page_size,…}`），
  // 不是裸数组。之前这里声明成 `ModelEndpoint[]`，后端一旦真实返回信封，页面 `.filter()` 会直接抛错
  // （只有后端 404 走 demo 兜底时才"看起来正常"），因此按平台约定改为 Paged。
  modelEndpoints: (query: ListQuery = {}) =>
    callApi<Paged<ModelEndpoint>>('/api/v1/models/endpoints', () => paginate(demo.demoModelEndpoints, query), {
      query: { ...query }, noFallback: true,
    }),
  routePolicies: () =>
    callApi<ModelRoutePolicy[]>('/api/v1/models/route-policies', () => demo.demoRoutePolicies, { noFallback: true }),
  saveRoutePolicy: (policy: Partial<ModelRoutePolicy> & { expectedVersion?: number }) =>
    callApi<ModelRoutePolicy | undefined>(
      `/api/v1/models/route-policies${policy.id ? `/${encodeURIComponent(policy.id)}` : ''}`,
      () => demo.demoRoutePolicies.find((item) => item.id === policy.id),
      { method: policy.id ? 'PUT' : 'POST', body: policy, noFallback: true },
    ),
  tokenUsage: (query: ListQuery = {}) =>
    callApi<Paged<TokenUsageRecord>>(
      '/api/v1/models/usage',
      () => paginate(sortBy(demo.demoTenantUsageRecords, 'ts'), query),
      { query: { ...query }, noFallback: true },
    ),
  modelUsage: () =>
    callApi<ModelUsageAggregate[]>('/api/v1/models/usage/aggregate', () => demo.demoModelUsage, { noFallback: true }),

  /* --- topology --- */
  topology: () => callApi<TopologyGraph>('/api/v1/topology', () => demo.demoTopology),

  /* --- findings & rules --- */
  findings: (filter: { severity?: string[]; domain?: string[]; status?: string[] } = {}, query: ListQuery = {}) =>
    callApi<Paged<Finding>>(
      '/api/v1/findings',
      () => {
        const filtered = demo.demoFindings.filter((finding) => {
          if (filter.severity?.length && !filter.severity.includes(finding.severity)) {
            return false;
          }
          if (filter.domain?.length && !filter.domain.includes(finding.domain)) {
            return false;
          }
          if (filter.status?.length && !filter.status.includes(finding.status)) {
            return false;
          }
          return true;
        });
        return paginate(sortBy(filtered, 'detectedAt'), query);
      },
      { query: findingQuery(filter, query) },
    ),
  updateFindingStatus: (id: string, status: FindingStatus) =>
    callApi<Finding | undefined>(
      `/api/v1/findings/${id}/status`,
      () => demo.demoFindings.find((finding) => finding.id === id),
      { method: 'POST', body: { status } },
    ),
  rules: (query: ListQuery & { domain?: string } = {}) =>
    callApi<Paged<Rule>>('/api/v1/rules', () => paginate(sortBy(demo.demoRules, 'hitCount24h'), query), {
      query: { ...query },
    }),
  ruleTest: (ruleId: string) =>
    callApi<RuleTestResult>(
      `/api/v1/rules/${ruleId}/test`,
      () => demo.buildRuleTestResult(ruleId),
      { method: 'POST' },
    ),
  updateRule: (ruleId: string, patch: { enabled?: boolean; rolloutPercent?: number; expectedVersion?: number }) =>
    callApi<Rule | undefined>(
      `/api/v1/rules/${ruleId}`,
      () => demo.demoRules.find((rule) => rule.id === ruleId),
      { method: 'PATCH', body: patch },
    ),

  /* --- red team --- */
  campaigns: (query: ListQuery & { state?: string; q?: string } = {}) =>
    callApi<Paged<Campaign>>('/api/v1/redteam/campaigns', () => paginate(demo.demoCampaigns, query), {
      query: { ...query }, noFallback: true,
    }),
  campaignResults: (campaignId: string) => callApi<CampaignResult[]>(
    `/api/v1/redteam/campaigns/${campaignId}/results`, () => [], { noFallback: true }),
  campaignReport: (campaignId: string) => callApi<CampaignReport | null>(
    `/api/v1/redteam/campaigns/${campaignId}/report`, () => null, { noFallback: true }),

  /* --- policies --- */
  policies: (query: ListQuery = {}) =>
    callApi<Paged<Policy>>('/api/v1/policies', () => paginate(sortBy(demo.demoPolicies, 'priority', 'asc'), query), {
      query: { ...query },
    }),
  savePolicy: (policy: Partial<Policy> & { id?: string }) =>
    callApi<Policy | undefined>(
      policy.id ? `/api/v1/policies/${policy.id}` : '/api/v1/policies',
      () => demo.demoPolicies.find((item) => item.id === policy.id),
      { method: policy.id ? 'PUT' : 'POST', body: policyBody(policy), noFallback: true },
    ),

  /* --- runtime --- */
  interceptPoints: () =>
    callApi<InterceptPointStatus[]>('/api/v1/runtime/intercept-points', () => demo.demoInterceptPoints),
  interceptEvents: () =>
    callApi<InterceptEvent[]>('/api/v1/runtime/events', () => demo.demoInterceptEvents),
  quotas: () => callApi<QuotaUsage[]>('/api/v1/runtime/quotas', () => demo.demoQuotaUsages),
  updateBlacklist: (id: string, enabled: boolean, expectedVersion: number) => callApi(`/api/v1/runtime/blacklists/${encodeURIComponent(id)}`, () => undefined,
    { method: 'PATCH', noFallback: true, body: { enabled, expected_version: expectedVersion } }),
  deleteBlacklist: (id: string, expectedVersion: number) => callApi(`/api/v1/runtime/blacklists/${encodeURIComponent(id)}?expected_version=${expectedVersion}`, () => undefined,
    { method: 'DELETE', noFallback: true }),
  blacklists: () =>
    callApi<BlacklistEntry[]>('/api/v1/runtime/blacklists', () => demo.demoBlacklists),
  addBlacklist: (entry: Pick<BlacklistEntry, 'kind' | 'pattern' | 'action' | 'scope' | 'note'>) =>
    callApi<BlacklistEntry>(
      '/api/v1/runtime/blacklists',
      () => ({
        id: `bl-local-${Date.now()}`,
        version: 1,
        enabled: true,
        hits24h: 0,
        updatedAt: new Date().toISOString(),
        ...entry,
      }),
      { method: 'POST', body: entry },
    ),
} as const;
