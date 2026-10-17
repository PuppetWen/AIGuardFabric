import { beforeEach, expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { schedulerNativeApi as api } from './schedulerNative';

vi.mock('./transport', () => ({ callApi: vi.fn().mockResolvedValue({ data: {} }) }));
beforeEach(() => vi.clearAllMocks());
const base = '/api/v1/alicloud/schedulerx3/native', id = '10000000-0000-4000-8000-000000000001';
it('uses only server-backed GETs for local state and original receipt paging with an abort signal', async () => {
  const controller = new AbortController(); await api.state(controller.signal); await api.receipt(id, 3, controller.signal);
  expect(callApi).toHaveBeenNthCalledWith(1, base, expect.any(Function), { noFallback: true, signal: controller.signal });
  expect(callApi).toHaveBeenNthCalledWith(2, `${base}/observations/${id}`, expect.any(Function),
    { noFallback: true, signal: controller.signal, query: { page: 3, page_size: 50 } });
});
it('keeps string int64 IDs, CAS and explicit Mock/Live intent without fabricating registration', async () => {
  const observe = { request_id: id, configuration_version: 7, confirm_live: true, initialize_mock_fixture: false };
  const replace = { action: 'replace' as const, request_id: id, expected_version: 3, configuration_version: 7,
    observation_id: id, bindings: [{ kind: 'report' as const, job_id: '9223372036854775807' }], confirm_local_only: true as const };
  const disable = { action: 'disable' as const, request_id: id, expected_version: 4 };
  const archive = { expected_generation: 8, request_ids: [id] };
  await api.observe(observe); await api.bind(replace); await api.bind(disable); await api.archive(archive);
  expect(vi.mocked(callApi).mock.calls.map(([path, , options]) => [path, options])).toEqual([
    [`${base}/observe`, { method: 'POST', body: observe, noFallback: true, timeoutMs: 130000 }],
    [`${base}/bindings`, { method: 'PUT', body: replace, noFallback: true }],
    [`${base}/bindings`, { method: 'PUT', body: disable, noFallback: true }],
    [`${base}/observations/archive`, { method: 'POST', body: archive, noFallback: true }],
  ]);
});
