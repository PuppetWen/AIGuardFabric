import type { WorkerQuotaBinding, WorkerQuotaRule, WorkerQuotas } from '@/types/agentTeamsQuotas';

export function compatibleWorkerQuota(rule: WorkerQuotaRule, assetId: string): boolean {
  return rule.enabled && rule.scope === 'agent' && rule.targetId === assetId
    && rule.dimension === 'tokens' && rule.window === 'day' && rule.onExceed === 'deny' && rule.limit > 0;
}

export function currentWorkerBinding(binding: WorkerQuotaBinding, data: WorkerQuotas): boolean {
  const rule = data.quotas.find(item => item.id === binding.quotaId);
  return data.inventoryAvailable && binding.enabled && binding.state !== 'stale'
    && binding.cloudVersion === data.cloudVersion && binding.mocked === data.mocked
    && data.workers.some(worker => worker.assetId === binding.assetId)
    && !!rule && compatibleWorkerQuota(rule, binding.assetId);
}

export function usableWorkerPreview(binding: WorkerQuotaBinding, data: WorkerQuotas, now: number): boolean {
  const preview = binding.observation;
  const rule = data.quotas.find(item => item.id === binding.quotaId);
  const observedAt = Date.parse(preview?.observedAt ?? '');
  return currentWorkerBinding(binding, data) && !binding.busy && binding.canObserve
    && !!preview?.previewUsable && Number.isFinite(observedAt) && now - observedAt < 300_000
    && preview.quotaVersion === rule?.version && preview.bindingVersion === binding.version
    && preview.cloudVersion === data.cloudVersion && preview.mocked === data.mocked
    && preview.limitType === 'token' && preview.periodType === 'day';
}

export function currentWorkerPreview(binding: WorkerQuotaBinding, data: WorkerQuotas): boolean {
  return usableWorkerPreview(binding, data, Date.now());
}
