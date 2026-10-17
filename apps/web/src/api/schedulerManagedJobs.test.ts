import { beforeEach, expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { schedulerManagedJobsApi as api } from './schedulerManagedJobs';
import type { ApplyInput, PreviewInput } from '@/pages/alicloud/scheduler-managed/types';
vi.mock('./transport', () => ({ callApi: vi.fn().mockResolvedValue({ data: {} }) }));
beforeEach(() => vi.clearAllMocks());
const base = '/api/v1/alicloud/schedulerx3/native/jobs', id = '10000000-0000-4000-8000-000000000001';
it('keeps local state, lost-preview lookup and original receipt strictly GET/server-only with abort signals', async () => {
  const controller = new AbortController(); await api.state(controller.signal); await api.readPreview(id, controller.signal); await api.receipt(id, controller.signal);
  expect(vi.mocked(callApi).mock.calls.map(([path, , options]) => [path, options])).toEqual([
    [base, { noFallback: true, signal: controller.signal }], [`${base}/previews/${id}`, { noFallback: true, signal: controller.signal }],
    [`${base}/operations/${id}`, { noFallback: true, signal: controller.signal }],
  ]);
  expect(() => vi.mocked(callApi).mock.calls[0][1]()).toThrow('Scheduler managed jobs require the server');
});
it('retains exact CAS, string int64 and explicit single-intent body without adding callback credentials', async () => {
  const draft: PreviewInput = { request_id: id, configuration_version: 5, expected_binding_version: 8,
    observation_id: id, change: { action: 'disable' }, selection: { kind: 'archive', app_id: '9007199254740993',
      job_id: '9223372036854775807', observation_fingerprint: 'a'.repeat(64) } };
  const confirm: ApplyInput = { preview_id: id, preview_fingerprint: 'b'.repeat(64), confirm_no_cloud_cas: true,
    confirm_callback_unknown: true, confirm_live: false, confirm_unknown_overlap: false };
  await api.preview(draft); await api.apply(id, confirm);
  expect(callApi).toHaveBeenNthCalledWith(1, `${base}/previews`, expect.any(Function), { noFallback: true, method: 'POST', body: draft });
  expect(callApi).toHaveBeenNthCalledWith(2, `${base}/operations/${id}`, expect.any(Function), { noFallback: true, method: 'PUT', body: confirm, timeoutMs: 130_000 });
});
it('uses separate explicit empty-body local recovery/readback and reviewed archive CAS/loss consent', async () => {
  await api.recover(id); await api.observeOriginal(id); await api.archive([id], 12);
  expect(vi.mocked(callApi).mock.calls.map(([path, , options]) => [path, options])).toEqual([
    [`${base}/operations/${id}/recover`, { noFallback: true, method: 'POST', body: {} }],
    [`${base}/operations/${id}/observe`, { noFallback: true, method: 'POST', body: {}, timeoutMs: 130_000 }],
    [`${base}/operations/archive`, { noFallback: true, method: 'POST', body: { expected_generation: 12, request_ids: [id], confirm_loss_of_preview: true } }],
  ]);
});
