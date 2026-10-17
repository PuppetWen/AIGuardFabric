import { afterEach, expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { agentTeamsQuotasApi } from './agentTeamsQuotas';

vi.mock('./transport', () => ({ callApi: vi.fn() }));
afterEach(() => vi.clearAllMocks());

it('keeps quota binding versions and never fabricates a successful cloud action', () => {
  agentTeamsQuotasApi.list();
  expect(callApi).toHaveBeenLastCalledWith('/api/v1/alicloud/agentteams/worker-quotas', expect.any(Function), { noFallback: true });
  const bind = { expected_version: 3, quota_id: 'quota-one', quota_version: 7, enabled: true };
  agentTeamsQuotasApi.bind('worker/asset', bind);
  expect(callApi).toHaveBeenLastCalledWith('/api/v1/alicloud/agentteams/worker-quotas/worker%2Fasset', expect.any(Function),
    { method: 'PUT', body: bind, noFallback: true });
  const observe = { request_id: 'request-one', expected_binding_version: 3,
    expected_quota_version: 7, configuration_version: 4, confirm_live: true };
  agentTeamsQuotasApi.observe('worker/asset', observe);
  expect(callApi).toHaveBeenLastCalledWith('/api/v1/alicloud/agentteams/worker-quotas/worker%2Fasset/observe', expect.any(Function),
    { method: 'POST', body: observe, noFallback: true, timeoutMs: 130_000 });
  const sync = { ...observe, request_id: 'request-two', preview_id: 'preview-one' };
  agentTeamsQuotasApi.sync('worker/asset', sync);
  expect(callApi).toHaveBeenLastCalledWith('/api/v1/alicloud/agentteams/worker-quotas/worker%2Fasset/sync', expect.any(Function),
    { method: 'POST', body: sync, noFallback: true, timeoutMs: 130_000 });
});
