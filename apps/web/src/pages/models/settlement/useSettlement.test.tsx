import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { gatewaySettlementApi as api, type SettlementReceipt } from '@/api/gatewaySettlement';
import type { ApiResult } from '@/api/dataSource';
import { ApiRequestError } from '@/api/transport';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import { useSettlement } from './useSettlement';
import { attempt, audit, deferred, receipt, result } from './testFixtures';
import { validReceipt } from './validation';

const original = useAuthStore.getState();
beforeEach(() => {
  useAuthStore.setState({ tenant: { id: 'one', slug: 'one' } as Tenant, sessionGeneration: 1 });
  vi.spyOn(api, 'read').mockResolvedValue(result(receipt()));
  vi.spyOn(api, 'recover').mockResolvedValue(result(receipt({ state: 'settled', chargeState: 'actual', auditId: audit, recoveryAvailable: false })));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); useAuthStore.setState(original); });
async function mount(canRead = true, canWrite = true) {
  const view = renderHook(() => useSettlement(canRead, canWrite));
  act(() => view.result.current.changeAttempt(attempt));
  await act(async () => { await view.result.current.read(); });
  return view;
}

it('does not read or recover on mount or input change and rejects invalid UUID before HTTP', async () => {
  const view = renderHook(() => useSettlement(true, true));
  expect(api.read).not.toHaveBeenCalled(); expect(api.recover).not.toHaveBeenCalled();
  act(() => view.result.current.changeAttempt('not-a-real-id'));
  await act(async () => { await view.result.current.read(); await view.result.current.recover(); });
  expect(api.read).not.toHaveBeenCalled(); expect(api.recover).not.toHaveBeenCalled();
});
it('normalizes an uppercase actual UUID and manually reads before offering recovery', async () => {
  const view = renderHook(() => useSettlement(true, true));
  act(() => view.result.current.changeAttempt(attempt.toUpperCase()));
  expect(view.result.current.canRecover).toBe(false);
  await act(async () => { await view.result.current.read(); });
  expect(api.read).toHaveBeenCalledWith(attempt, expect.any(AbortSignal));
  expect(view.result.current.canRecover).toBe(true); expect(api.recover).not.toHaveBeenCalled();
});
it('requires current read and write capabilities in handlers', async () => {
  const noRead = await mount(false, true);
  await act(async () => { await noRead.result.current.recover(); });
  expect(api.read).not.toHaveBeenCalled(); noRead.unmount();
  const reader = await mount(true, false);
  await act(async () => { await reader.result.current.recover(); });
  expect(api.recover).not.toHaveBeenCalled(); expect(reader.result.current.canRecover).toBe(false);
});
it('synchronously fences duplicate recovery and never creates a new attempt ID', async () => {
  const slow = deferred<ApiResult<SettlementReceipt>>(); vi.mocked(api.recover).mockReturnValue(slow.promise);
  const view = await mount(); let first!: Promise<void>;
  act(() => { first = view.result.current.recover(); void view.result.current.recover(); view.result.current.changeAttempt(audit); });
  expect(api.recover).toHaveBeenCalledTimes(1); expect(view.result.current.attempt).toBe(attempt);
  await act(async () => { slow.resolve(result(receipt({ state: 'settled', auditId: audit, recoveryAvailable: false }))); await first; });
  expect(view.result.current.canRecover).toBe(false); expect(view.result.current.unknown).toBe(false);
});
it('a lost recovery reply and receipt 404 retain the original ID and forbid further POST', async () => {
  vi.mocked(api.recover).mockRejectedValue(new ApiRequestError('Lost reply', 0, 'network'));
  const view = await mount(); await act(async () => { await view.result.current.recover(); });
  vi.mocked(api.read).mockRejectedValue(new ApiRequestError('No receipt', 404, 'not-found'));
  await act(async () => { await view.result.current.read(); await view.result.current.recover(); });
  act(() => view.result.current.changeAttempt(audit));
  expect(view.result.current.unknown).toBe(true); expect(view.result.current.attempt).toBe(attempt);
  expect(api.recover).toHaveBeenCalledTimes(1);
});
it('a trusted GET after lost reply permits only a new explicit local recovery of the same ID', async () => {
  vi.mocked(api.recover).mockRejectedValueOnce(new ApiRequestError('Timeout', 408, 'timeout'));
  const view = await mount(); await act(async () => { await view.result.current.recover(); await view.result.current.read(); });
  expect(api.recover).toHaveBeenCalledTimes(1); expect(view.result.current.canRecover).toBe(true);
  await act(async () => { await view.result.current.recover(); });
  expect(api.recover).toHaveBeenNthCalledWith(2, attempt, expect.any(AbortSignal));
});
it('an invalid successful recovery response cannot unlock the unknown original result', async () => {
  vi.mocked(api.recover).mockResolvedValue(result(receipt({ mayExecute: true } as never)));
  const view = await mount(); await act(async () => { await view.result.current.recover(); await view.result.current.recover(); });
  expect(view.result.current.unknown).toBe(true); expect(api.recover).toHaveBeenCalledTimes(1);
});
it('ignores a late read and aborts its request on unmount', async () => {
  const slow = deferred<ApiResult<SettlementReceipt>>(); vi.mocked(api.read).mockReturnValue(slow.promise);
  const view = renderHook(() => useSettlement(true, true)); let read!: Promise<void>;
  act(() => { view.result.current.changeAttempt(attempt); });
  act(() => { read = view.result.current.read(); });
  const signal = vi.mocked(api.read).mock.calls[0][1]!; view.unmount();
  expect(signal.aborted).toBe(true);
  await act(async () => { slow.resolve(result(receipt())); await read; });
  expect(view.result.current.receipt).toBeNull();
});
it('does not publish a late recovery after tenant A to B to A with another session', async () => {
  const slow = deferred<ApiResult<SettlementReceipt>>(); vi.mocked(api.recover).mockReturnValue(slow.promise);
  const view = await mount(); let write!: Promise<void>;
  act(() => { write = view.result.current.recover(); });
  act(() => useAuthStore.setState({ tenant: { id: 'two', slug: 'two' } as Tenant, sessionGeneration: 2 }));
  act(() => useAuthStore.setState({ tenant: { id: 'one', slug: 'one' } as Tenant, sessionGeneration: 3 }));
  await act(async () => { slow.resolve(result(receipt({ state: 'settled', auditId: audit, recoveryAvailable: false }))); await write; });
  expect(view.result.current.receipt?.state).toBe('pending-audit'); expect(view.result.current.unknown).toBe(true);
});
it('rejects unsafe or inconsistent receipt authority and component values', () => {
  expect(validReceipt(receipt({ components: [{ usageId: audit, evidence: 'sent-usage-known', costMicro: 0 }] }), attempt)).toBe(true);
  expect(validReceipt(receipt({ components: [{ usageId: audit, evidence: 'sent-usage-known', costMicro: Number.MAX_SAFE_INTEGER + 1 }] }), attempt)).toBe(false);
  expect(validReceipt(receipt({ state: 'settled', auditId: null, recoveryAvailable: false }), attempt)).toBe(false);
  expect(validReceipt(receipt({ attemptId: audit }), attempt)).toBe(false);
  expect(validReceipt(receipt({ mayExecute: true } as never), attempt)).toBe(false);
});
