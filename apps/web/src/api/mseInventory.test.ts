import { afterEach, expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { mseInventoryApi } from './mseInventory';
import { mseInventory, mseOperation, mseRequest, mseResult } from '@/pages/alicloud/mse/mseFixtures';
vi.mock('./transport', () => ({ callApi: vi.fn() }));
afterEach(() => vi.clearAllMocks());

it('reads original receipts without dispatch and sends a bounded live-confirmed inventory once with the original UUID', async () => {
  vi.mocked(callApi).mockResolvedValue(mseResult(mseInventory()));
  const abort = new AbortController();
  await mseInventoryApi.list(abort.signal);
  expect(callApi).toHaveBeenLastCalledWith('/api/v1/alicloud/mse/inventory', expect.any(Function), { noFallback: true, signal: abort.signal });
  vi.mocked(callApi).mockResolvedValue(mseResult(mseOperation()));
  await mseInventoryApi.receipt(mseRequest, abort.signal);
  expect(callApi).toHaveBeenLastCalledWith(`/api/v1/alicloud/mse/inventory/operations/${mseRequest}`, expect.any(Function),
    { noFallback: true, signal: abort.signal });
  const body = { request_id: mseRequest, configuration_version: 4, confirm_live: true };
  await mseInventoryApi.sync(body, abort.signal);
  expect(callApi).toHaveBeenLastCalledWith('/api/v1/alicloud/mse/inventory/sync', expect.any(Function),
    { noFallback: true, method: 'POST', body, signal: abort.signal, timeoutMs: 130_000 });
  expect(callApi).toHaveBeenCalledTimes(3);
  expect(() => vi.mocked(callApi).mock.calls[0][1]()).toThrow(/requires the server/);
});
it('cancel and archive are explicit local POSTs with no current configuration or cloud confirmation requirement', async () => {
  vi.mocked(callApi).mockResolvedValue(mseResult(mseOperation({ status: 'cancelled' })));
  await mseInventoryApi.cancel(mseRequest);
  expect(callApi).toHaveBeenLastCalledWith(`/api/v1/alicloud/mse/inventory/operations/${mseRequest}/cancel`, expect.any(Function),
    { noFallback: true, method: 'POST', body: {} });
  const body = { expected_generation: 7, request_ids: [mseRequest] };
  vi.mocked(callApi).mockResolvedValue(mseResult({ generation: 8, archivedCount: 1, archivedRequestIds: [mseRequest] }));
  await mseInventoryApi.archive(body);
  expect(callApi).toHaveBeenLastCalledWith('/api/v1/alicloud/mse/operations/archive', expect.any(Function),
    { noFallback: true, method: 'POST', body });
  expect(callApi).toHaveBeenCalledTimes(2);
});
