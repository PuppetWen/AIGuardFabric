import { describe, expect, it } from 'vitest';
import { bindingFixture, quotaFixture, quotasFixture } from './workerQuotaFixtures';
import { compatibleWorkerQuota, currentWorkerBinding, usableWorkerPreview } from './workerQuotaState';

describe('Worker quota preview eligibility', () => {
  it('requires a positive enabled deny token day rule targeted to exactly this Worker', () => {
    expect(compatibleWorkerQuota(quotaFixture, 'asset-one')).toBe(true);
    for (const change of [{ enabled: false }, { scope: 'tenant' as const }, { targetId: null },
      { targetId: 'other-asset' }, { dimension: 'requests' as const }, { window: 'hour' as const },
      { limit: 0 }, { limit: -1 }, { onExceed: 'audit' }]) {
      expect(compatibleWorkerQuota({ ...quotaFixture, ...change }, 'asset-one')).toBe(false);
    }
  });

  it('rejects consumed, expired, wrong version, wrong mode and unsupported cloud previews', () => {
    const data = quotasFixture();
    const row = data.items[0];
    const now = Date.now();
    expect(usableWorkerPreview(row, data, now)).toBe(true);
    for (const change of [{ previewUsable: false }, { observedAt: new Date(now - 300_000).toISOString() },
      { observedAt: 'invalid' }, { quotaVersion: 6 }, { cloudVersion: 3 }, { bindingVersion: 2 },
      { mocked: true }, { limitType: 'Token' }, { periodType: 'month' }]) {
      expect(usableWorkerPreview({ ...row, observation: { ...row.observation!, ...change } }, data, now)).toBe(false);
    }
    expect(usableWorkerPreview({ ...row, observation: null }, data, now)).toBe(false);
    expect(usableWorkerPreview({ ...row, busy: true }, data, now)).toBe(false);
    expect(usableWorkerPreview({ ...row, canObserve: false }, data, now)).toBe(false);
  });

  it('invalidates old previews after rule updates and identity changes', () => {
    const row = bindingFixture();
    const data = quotasFixture();
    const updated = { ...data, quotas: [{ ...quotaFixture, version: 8, limit: 2000 }] };
    expect(currentWorkerBinding(row, updated)).toBe(true);
    expect(usableWorkerPreview(row, updated, Date.now())).toBe(false);
    for (const change of [{ inventoryAvailable: false }, { cloudVersion: 5 }, { mocked: true }, { workers: [] }, { quotas: [] }]) {
      expect(currentWorkerBinding(row, { ...data, ...change })).toBe(false);
    }
    expect(currentWorkerBinding({ ...row, enabled: false }, data)).toBe(false);
    expect(currentWorkerBinding({ ...row, state: 'stale' }, data)).toBe(false);
  });
});
