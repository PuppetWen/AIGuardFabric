import type { WorkerQuotaBinding, WorkerQuotaRule, WorkerQuotas } from '@/types/agentTeamsQuotas';

export const quotaFixture: WorkerQuotaRule = { id: 'quota-one', name: 'Worker daily budget', version: 7,
  targetId: 'asset-one', scope: 'agent', dimension: 'tokens', window: 'day', limit: 1000, enabled: true, onExceed: 'deny' };

export function bindingFixture(): WorkerQuotaBinding {
  return { assetId: 'asset-one', workerName: 'support-worker', version: 3, quotaId: quotaFixture.id,
    quotaVersion: 7, quotaName: quotaFixture.name, platformLimit: 1000, cloudVersion: 4, scopeId: 'scope-one', mocked: false,
    enabled: true, state: 'drift', busy: false, canObserve: true, leaseExpiresAt: null, driftAlertId: null,
    boundAt: '2026-09-20T10:00:00Z', lastOperation: null,
    observation: { id: 'preview-one', observedAt: new Date(Date.now() - 60_000).toISOString(), quotaVersion: 7,
      cloudVersion: 4, bindingVersion: 3, mocked: false, previewUsable: true, usageLimit: 500,
      limitType: 'token', periodType: 'day', ruleStatus: null, usedAmount: null, overLimit: null } };
}

export function quotasFixture(): WorkerQuotas {
  return { inventoryAvailable: true, cloudVersion: 4, mocked: false, canWrite: true,
    workers: [{ assetId: 'asset-one', name: 'support-worker' }], quotas: [quotaFixture], items: [bindingFixture()] };
}
