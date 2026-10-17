import type {
  Adapter,
  AgentTeam,
  Alert,
  AuditEntry,
  Case,
  CaseTimelineEntry,
  ChainCheckResult,
  CrossTeamCall,
  EscalationRoute,
  ListQuery,
  LogSource,
  Paged,
  Parser,
  ReportJob,
  SelfCheckItem,
  ServiceBinding,
  SoarRun,
} from '@/types/domain';

import type { RawReplayResponse } from './contract';
import type { ApiResult } from './dataSource';
import * as demo from './demo';
import { paginate, sortBy } from './pagination';
import { callApi } from './transport';
import { logSourcesApi, type SourceInput } from './logSources';

const cloudUnavailable = (): never => { throw new Error('云数据需要连接后端 / Cloud data requires the server'); };

/**
 * Endpoint surface, part two (ingest → reports).
 *
 * Assembled together with `./endpoints` into the single exported `api` object by
 * `./client`; property order is preserved by the spread there.
 */
export const operationsEndpoints = {
  /* --- ingest --- */
  // 同 `campaigns`：`/ingest/sources` 与 `/ingest/parsers` 在平台侧也是分页信封（别名指到 /sources、/parsers）。
  logSources: (query: ListQuery = {}) =>
    callApi<Paged<LogSource> & { canWrite?: boolean }>('/api/v1/ingest/sources', () => paginate(demo.demoLogSources, query), {
      query: { ...query },
    }),
  parsers: (query: ListQuery & { engine?: string } = {}) =>
    callApi<Paged<Parser>>('/api/v1/ingest/parsers', () => paginate(demo.demoParsers, query), {
      query: { ...query },
    }),
  /**
   * 原始日志只读预览。
   *
   * GET 返回 `{ raw_logs: [{ payload, … }], preview_only: true }`，不会标记日志或生成事件；
   * 明确执行的 POST 在 `SourceReplay` 中展示回放统计及命中解析器。
   * 控制台"回放样例"视图只需要逐行原文。
   * 这里做一次收敛：把 `raw_logs[].payload` 抽成 `string[]` 交给页面，**保持页面契约不变**；
   * demo 兜底本来就是 `string[]`，原样返回。
   */
  replay: async (sourceId: string): Promise<ApiResult<string[]>> => {
    const result = await callApi<string[] | RawReplayResponse>(
      '/api/v1/ingest/replay',
      () => demo.demoReplaySamples[sourceId] ?? [],
      { query: { sourceId } },
    );
    if (result.meta.source === 'demo') {
      return result as ApiResult<string[]>;
    }
    const raw = result.data as RawReplayResponse;
    const lines = (raw.rawLogs ?? []).map((item) => item.payload ?? '').filter((line) => line.length > 0);
    return { ...result, data: lines };
  },
  createLogSource: (payload: SourceInput) => logSourcesApi.save(payload),

  /* --- alerts --- */
  alerts: (query: ListQuery & { severity?: string; state?: string; domain?: string } = {}) =>
    callApi<Paged<Alert> & { canWrite?: boolean }>('/api/v1/alerts', () => paginate(sortBy(demo.demoAlerts, 'lastSeenAt'), query), {
      query: { ...query },
    }),
  escalationRoutes: () =>
    callApi<EscalationRoute[]>('/api/v1/alerts/escalation-routes', () => demo.demoEscalationRoutes),
  updateAlertStatus: (id: string, status: string) =>
    callApi<Alert | undefined>(
      `/api/v1/alerts/${id}/status`,
      () => demo.demoAlerts.find((alert) => alert.id === id),
      { method: 'POST', body: { status }, noFallback: true },
    ),

  /* --- cases --- */
  // 同 `campaigns`：`/api/v1/cases` 在平台侧是分页信封，这里改为 Paged。
  cases: (query: ListQuery = {}) =>
    callApi<Paged<Case> & {canWrite?: boolean}>('/api/v1/cases', () => paginate(demo.demoCases, query), { query: { ...query } }),
  caseTimeline: (caseId: string) =>
    callApi<CaseTimelineEntry[]>(
      `/api/v1/cases/${caseId}/timeline`,
      () => {
        const target = demo.demoCases.find((item) => item.id === caseId);
        return target ? demo.timelineForCase(target) : [];
      },
    ),
  soarRuns: (caseId: string) =>
    callApi<SoarRun[]>(`/api/v1/cases/${caseId}/soar-runs`, () => demo.soarRunsForCase(caseId)),

  /* --- integrations --- */
  adapters: () => callApi<Adapter[]>('/api/v1/integrations/adapters', () => demo.demoAdapters),
  saveAdapter: (payload: Partial<Adapter> & { id: string }) =>
    callApi<Adapter | undefined>(
      `/api/v1/integrations/adapters/${payload.id}`,
      () => demo.demoAdapters.find((adapter) => adapter.id === payload.id),
      { method: 'PUT', body: payload },
    ),

  /* --- Alibaba Cloud AgentTeams --- */
  agentTeams: () => callApi<AgentTeam[]>('/api/v1/alicloud/agentteams', cloudUnavailable, { noFallback: true }),
  crossTeamCalls: () =>
    callApi<CrossTeamCall[]>('/api/v1/alicloud/cross-team-calls', cloudUnavailable, { noFallback: true }),
  serviceBindings: () =>
    callApi<ServiceBinding[]>('/api/v1/alicloud/service-bindings', cloudUnavailable, { noFallback: true }),
  selfCheck: () =>
    callApi<SelfCheckItem[]>('/api/v1/alicloud/self-check', cloudUnavailable, {
      method: 'GET', noFallback: true,
    }),

  /* --- audit --- */
  auditEntries: (query: ListQuery & { actor?: string; outcome?: string; sensitive_only?: boolean } = {}) =>
    callApi<Paged<AuditEntry>>(
      '/api/v1/audit',
      () => {
        const rows = demo.demoAuditEntries.filter((entry) => {
          if (query.actor && entry.actor.toLowerCase() !== query.actor.toLowerCase()) return false;
          if (query.outcome && entry.result !== query.outcome) return false;
          if (query.sensitive_only && !entry.sensitive) return false;
          if (!query.keyword) return true;
          const searchable = `${entry.action} ${entry.actor} ${entry.resourceName} ${entry.resourceId} ${entry.detail}`.toLowerCase();
          return searchable.includes(query.keyword.toLowerCase());
        });
        return paginate(sortBy(rows, 'ts'), { ...query, keyword: undefined });
      },
      { query: { ...query } },
    ),
  verifyChain: () => callApi<ChainCheckResult>('/api/v1/audit/verify', () => demo.verifyAuditChain()),

  /* --- reports --- */
  // 同 `campaigns`：`/api/v1/reports` 在平台侧是分页信封，这里改为 Paged。
  reports: (query: ListQuery & { kind?: string } = {}) =>
    callApi<Paged<ReportJob>>('/api/v1/reports', () => paginate(demo.demoReports, query), { query: { ...query } }),
  generateReport: (payload: { type: ReportJob['type']; windowDays: number; format: string }) =>
    callApi<ReportJob>(
      '/api/v1/reports',
      () => ({
        id: `rpt-local-${Date.now()}`,
        name: `新报表（${payload.type}）`,
        type: payload.type,
        format: payload.format as ReportJob['format'],
        schedule: 'manual' as const,
        windowDays: payload.windowDays,
        status: 'ready' as const,
        sizeKb: 512,
        createdAt: new Date().toISOString(),
        createdBy: '当前用户',
        recipients: [],
        preview: '# 新报表\n\n演示模式下由前端生成的样例报表内容。',
      }),
      { method: 'POST', body: {
        kind: payload.type === 'executive' ? 'posture' : payload.type,
        window_secs: payload.windowDays * 86400,
        format: payload.format,
      }, noFallback: true },
    ),
} as const;
