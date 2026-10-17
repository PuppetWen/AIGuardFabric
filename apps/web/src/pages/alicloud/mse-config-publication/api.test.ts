import { beforeEach, expect, it, vi } from 'vitest';
import { callApi } from '@/api/transport';
import { publicationApi } from './api';
import { operationId, policyId } from './testFixtures';
vi.mock('@/api/transport', () => ({ callApi: vi.fn() }));
beforeEach(() => { vi.clearAllMocks(); });
const base = '/api/v1/alicloud/mse/config-publication';
it('uses no-fallback local GETs without implicit recovery or cloud observation', async () => {
  const controller = new AbortController();
  await publicationApi.state(controller.signal); await publicationApi.receipt(operationId, controller.signal); await publicationApi.policies(2, controller.signal);
  expect(vi.mocked(callApi).mock.calls.map(row => [row[0], row[2]])).toEqual([
    [base, { noFallback: true, signal: controller.signal }], [`${base}/operations/${operationId}`, { noFallback: true, signal: controller.signal }],
    ['/api/v1/policies', { noFallback: true, signal: controller.signal, query: { page: 2, pageSize: 50 } }],
  ]);
});
it('sends exact versions and explicit confirmations without target overrides or browser content', async () => {
  const observe = { request_id: operationId, configuration_version: 3, confirm_live: false };
  const preview = { request_id: operationId, configuration_version: 3, observation_id: operationId, expected_state_version: 7,
    change: { action: 'publish' as const, policies: [{ policy_id: policyId, version: 4 }] } };
  const apply = { request_id: operationId, preview_id: operationId, expected_state_version: 7,
    confirm_apply: true, confirm_upsert: true, confirm_live: false, confirm_unknown_overlap: false };
  await publicationApi.observe(observe); await publicationApi.preview(preview); await publicationApi.apply(apply);
  expect(vi.mocked(callApi).mock.calls.map(row => row[2])).toEqual([observe, preview, apply].map(body => ({ noFallback: true, method: 'POST', timeoutMs: 130000, body })));
});
it('uses the dedicated local empty-body recovery and captured archive generation', async () => {
  await publicationApi.observeOriginal(operationId, { request_id: policyId, configuration_version: 5, confirm_live: true });
  await publicationApi.recover(operationId); await publicationApi.archive({ expected_generation: 11, request_ids: [operationId] });
  expect(callApi).toHaveBeenNthCalledWith(1, `${base}/operations/${operationId}/observe`, expect.any(Function),
    expect.objectContaining({ body: { request_id: policyId, configuration_version: 5, confirm_live: true } }));
  expect(callApi).toHaveBeenNthCalledWith(2, `${base}/operations/${operationId}/recover`, expect.any(Function),
    expect.objectContaining({ method: 'POST', body: {}, noFallback: true }));
  expect(callApi).toHaveBeenNthCalledWith(3, `${base}/operations/archive`, expect.any(Function),
    expect.objectContaining({ body: { expected_generation: 11, request_ids: [operationId] } }));
});
