import { afterEach, expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { privatelinkInventoryApi } from './privatelinkInventory';
import { privatelinkInventory, privatelinkOperation, privatelinkRequest, privatelinkResult } from '@/pages/alicloud/privatelink/privatelinkFixtures';
vi.mock('./transport', () => ({ callApi: vi.fn() }));
afterEach(() => vi.clearAllMocks());

it('reads original receipts without dispatch and sends a bounded live-confirmed inventory once with the original UUID', async () => {
  vi.mocked(callApi).mockResolvedValue(privatelinkResult(privatelinkInventory()));
  const abort = new AbortController();
  await privatelinkInventoryApi.list(abort.signal);
  expect(callApi).toHaveBeenLastCalledWith('/api/v1/alicloud/privatelink/inventory', expect.any(Function), { noFallback: true, signal: abort.signal });
  vi.mocked(callApi).mockResolvedValue(privatelinkResult(privatelinkOperation()));
  await privatelinkInventoryApi.receipt(privatelinkRequest, abort.signal);
  expect(callApi).toHaveBeenLastCalledWith(`/api/v1/alicloud/privatelink/inventory/operations/${privatelinkRequest}`, expect.any(Function),
    { noFallback: true, signal: abort.signal });
  const body = { request_id: privatelinkRequest, configuration_version: 4, confirm_live: true };
  await privatelinkInventoryApi.sync(body, abort.signal);
  expect(callApi).toHaveBeenLastCalledWith('/api/v1/alicloud/privatelink/inventory/sync', expect.any(Function),
    { noFallback: true, method: 'POST', body, signal: abort.signal, timeoutMs: 130_000 });
  expect(callApi).toHaveBeenCalledTimes(3);
  expect(() => vi.mocked(callApi).mock.calls[0][1]()).toThrow(/requires the server/);
});
it('cancel and archive are explicit local POSTs with no current configuration or cloud confirmation requirement', async () => {
  vi.mocked(callApi).mockResolvedValue(privatelinkResult(privatelinkOperation({ status: 'cancelled' })));
  await privatelinkInventoryApi.cancel(privatelinkRequest);
  expect(callApi).toHaveBeenLastCalledWith(`/api/v1/alicloud/privatelink/inventory/operations/${privatelinkRequest}/cancel`, expect.any(Function),
    { noFallback: true, method: 'POST', body: {} });
  const body = { expected_generation: 7, request_ids: [privatelinkRequest] };
  vi.mocked(callApi).mockResolvedValue(privatelinkResult({ generation: 8, archivedCount: 1, archivedRequestIds: [privatelinkRequest] }));
  await privatelinkInventoryApi.archive(body);
  expect(callApi).toHaveBeenLastCalledWith('/api/v1/alicloud/privatelink/operations/archive', expect.any(Function),
    { noFallback: true, method: 'POST', body });
  expect(callApi).toHaveBeenCalledTimes(2);
});
