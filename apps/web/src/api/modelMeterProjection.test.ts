import { afterEach, expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { modelMeterProjectionApi } from './modelMeterProjection';
vi.mock('./transport', () => ({ callApi: vi.fn() }));
afterEach(() => vi.resetAllMocks());
const data = { scope: 'node', readOnly: true, committedProjectionIncomplete: false, committedGroupsMerged: false,
  maxUsageRecordsPerTenant: 512, maxFactsPerTenant: 512, maxWitnessBytesPerTenant: 8_388_608 };
it('reads projection status with abort and no fallback, body, provider or mutation', async () => {
  const signal = new AbortController().signal;
  vi.mocked(callApi).mockResolvedValue({ data, meta: { source: 'live', elapsedMs: 0, at: 0 } });
  expect((await modelMeterProjectionApi.read(signal)).data).toEqual(data);
  expect(callApi).toHaveBeenCalledExactlyOnceWith('/api/v1/models/usage/projection-status', expect.any(Function),
    { noFallback: true, signal });
});
it.each([undefined, 'false'])('rejects incomplete=%s as unknown instead of interpreting it as complete', async flag => {
  vi.mocked(callApi).mockResolvedValue({ data: { ...data, committedProjectionIncomplete: flag },
    meta: { source: 'live', elapsedMs: 0, at: 0 } });
  await expect(modelMeterProjectionApi.read()).rejects.toThrow('Projection coverage status is invalid');
});
