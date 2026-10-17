import { callApi } from './transport';

export type RuntimeQuotaScope = 'tenant' | 'agent' | 'session';
export type RuntimeQuotaDimension = 'requests' | 'tokens' | 'concurrency' | 'cost';
export type RuntimeQuotaWindow = 'minute' | 'hour' | 'day' | 'month' | 'session' | 'total';
export type RuntimeQuotaAction = 'deny' | 'throttle' | 'quota' | 'audit' | 'allow';

export interface RuntimeQuotaDefinition {
  id: string; name: string; scope: RuntimeQuotaScope; dimension: RuntimeQuotaDimension;
  window: RuntimeQuotaWindow; limit: number; softThreshold: number; onExceed: RuntimeQuotaAction;
  enabled: boolean; version: number; targetId?: string | null;
}
export interface RuntimeQuotaDraft {
  name: string; scope: RuntimeQuotaScope; dimension: RuntimeQuotaDimension; window: RuntimeQuotaWindow;
  limit: number; softThreshold?: number | null; action: RuntimeQuotaAction; enabled: boolean; targetId?: string;
}
export interface RuntimeQuotaEntry { quota: RuntimeQuotaDefinition; used: number; remaining: number }
interface QuotaPage { items: RuntimeQuotaEntry[]; total: number; page: number; pageSize: number; hasMore: boolean }

export const runtimeQuotaConfiguration = {
  list: (page = 1, keyword = '', pageSize = 8, signal?: AbortSignal) => callApi<QuotaPage>('/api/v1/quotas', () => null as never,
    { noFallback: true, signal, query: { page, page_size: pageSize, q: keyword } }),
  save: (draft: RuntimeQuotaDraft, expectedVersion: number) => callApi<{ quota: RuntimeQuotaDefinition }>(
    '/api/v1/quotas', () => null as never, { method: 'POST', noFallback: true, body: {
      name: draft.name.trim(), scope: draft.scope, dimension: draft.dimension, window: draft.window,
      limit: draft.limit, soft_threshold: draft.softThreshold ?? null, action: draft.action,
      enabled: draft.enabled, target_id: draft.scope === 'agent' ? draft.targetId?.trim() || null : null,
      expected_version: expectedVersion,
    } }),
  latest: async (name: string): Promise<RuntimeQuotaDefinition> => {
    for (let page = 1; ; page += 1) {
      const result = await runtimeQuotaConfiguration.list(page, name, 100);
      const matched = result.data.items.find(entry => entry.quota.name === name);
      if (matched) return matched.quota;
      if (!result.data.hasMore) throw new Error('Quota was not found in the current tenant / 当前组织未找到该配额');
    }
  },
};
