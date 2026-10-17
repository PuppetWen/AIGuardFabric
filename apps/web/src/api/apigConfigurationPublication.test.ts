import { beforeEach, expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { apigConfigurationApi as api } from './apigConfigurationPublication';
vi.mock('./transport', () => ({ callApi: vi.fn().mockResolvedValue({ data: {} }) }));
beforeEach(() => vi.clearAllMocks());
const base = '/api/v1/alicloud/apig/configuration-publication', id = '10000000-0000-4000-8000-000000000001';
it('reads local state and original receipts with explicit cancellation and no fallback data', async () => {
  const controller = new AbortController(); await api.state(controller.signal); await api.receipt(id, controller.signal);
  expect(callApi).toHaveBeenNthCalledWith(1, base, expect.any(Function), { noFallback: true, signal: controller.signal });
  expect(callApi).toHaveBeenNthCalledWith(2, `${base}/operations/${id}`, expect.any(Function), { noFallback: true, signal: controller.signal });
});
it('preserves strict bodies and separates empty local recovery from a provider configuration write', async () => {
  const observe = { request_id: id, configuration_version: 7, confirm_live: true, initialize_mock_fixture: false };
  const preview = { request_id: id, configuration_version: 7, observation_id: id, expected_state_version: 3,
    change: { action: 'content' as const, settings: { enabled: true, checkRequest: true, checkResponse: false, denyCode: 403 } } };
  const apply = { request_id: id, preview_id: id, expected_state_version: 3, confirm_apply: true, confirm_preserved_private_configuration: true,
    confirm_streaming_or_shared_impact: true, confirm_no_cloud_cas: true, confirm_live: true, confirm_unknown_overlap: false };
  const archive = { expected_generation: 9, request_ids: [id] }; await api.observe(observe); await api.preview(preview); await api.apply(apply);
  await api.observeOriginal(id, observe); await api.recover(id); await api.archive(archive);
  expect(vi.mocked(callApi).mock.calls.map(([path, , options]) => [path, options])).toEqual([
    [`${base}/observe`, { noFallback: true, method: 'POST', body: observe, timeoutMs: 130000 }],
    [`${base}/previews`, { noFallback: true, method: 'POST', body: preview, timeoutMs: 130000 }],
    [`${base}/operations`, { noFallback: true, method: 'POST', body: apply, timeoutMs: 130000 }],
    [`${base}/operations/${id}/observe`, { noFallback: true, method: 'POST', body: observe, timeoutMs: 130000 }],
    [`${base}/operations/${id}/recover`, { noFallback: true, method: 'POST', body: {}, timeoutMs: 130000 }],
    [`${base}/operations/archive`, { noFallback: true, method: 'POST', body: archive, timeoutMs: 130000 }],
  ]);
});
