import { beforeEach, expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { apigPublicationApi as api } from './apigPolicyPublication';

vi.mock('./transport', () => ({ callApi: vi.fn().mockResolvedValue({ data: {} }) }));
beforeEach(() => vi.clearAllMocks());
const base = '/api/v1/alicloud/apig/policy-publication', id = '10000000-0000-4000-8000-000000000001';
it('reads typed local state with explicit server pagination and a caller-owned abort signal', async () => {
  const controller = new AbortController(), query = { source_page: 3, source_page_size: 20, source_eligible_only: true };
  await api.state(query, controller.signal); await api.receipt(id, controller.signal);
  expect(callApi).toHaveBeenNthCalledWith(1, base, expect.any(Function), { noFallback: true, signal: controller.signal, query });
  expect(callApi).toHaveBeenNthCalledWith(2, `${base}/operations/${id}`, expect.any(Function), { noFallback: true, signal: controller.signal });
});
it('keeps the strict native bodies and local-only empty recovery separate from provider publication', async () => {
  const observation = { request_id: id, configuration_version: 7, confirm_live: true, initialize_mock_fixture: false };
  const preview = { request_id: id, configuration_version: 7, observation_id: id, expected_state_version: 3,
    change: { action: 'publish' as const, policies: [{ policy_id: id, version: 4 }] } };
  const apply = { request_id: id, preview_id: id, expected_state_version: 3, confirm_apply: true, confirm_scope_difference: true,
    confirm_shared_policy_impact: true, confirm_no_cloud_cas: true, confirm_live: true, confirm_unknown_overlap: false };
  await api.observe(observation); await api.preview(preview); await api.apply(apply); await api.observeOriginal(id, observation); await api.recover(id);
  await api.archive({ expected_generation: 9, request_ids: [id] });
  expect(vi.mocked(callApi).mock.calls.map(([path, , options]) => [path, options])).toEqual([
    [`${base}/observe`, { noFallback: true, method: 'POST', body: observation, timeoutMs: 130000 }],
    [`${base}/previews`, { noFallback: true, method: 'POST', body: preview, timeoutMs: 130000 }],
    [`${base}/operations`, { noFallback: true, method: 'POST', body: apply, timeoutMs: 130000 }],
    [`${base}/operations/${id}/observe`, { noFallback: true, method: 'POST', body: observation, timeoutMs: 130000 }],
    [`${base}/operations/${id}/recover`, { noFallback: true, method: 'POST', body: {} }],
    [`${base}/operations/archive`, { noFallback: true, method: 'POST', body: { expected_generation: 9, request_ids: [id] } }],
  ]);
});
