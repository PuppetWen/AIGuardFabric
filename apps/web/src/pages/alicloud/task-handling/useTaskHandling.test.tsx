import { act, renderHook } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { taskHandlingApi } from '@/api/agentTeamsTaskHandling';
import { ApiRequestError } from '@/api/client';
import type { ApiResult } from '@/api/dataSource';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import type { HandlingPage } from '@/types/agentTeamsTaskHandling';
import { useTaskHandling } from './useTaskHandling';
import { deferred, event, eventId, page, receipt, requestId, result } from './testFixtures';

const original = useAuthStore.getState();
beforeEach(() => {
  useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 1 });
  vi.spyOn(taskHandlingApi, 'list').mockResolvedValue(result(page()));
  vi.spyOn(taskHandlingApi, 'event').mockResolvedValue(result(event()));
  vi.spyOn(taskHandlingApi, 'resolve').mockImplementation(async (_, input) => result(receipt({ requestId: input.request_id })));
  vi.spyOn(taskHandlingApi, 'archive').mockImplementation(async input => result(receipt({ purpose: 'operator-archive', requestId: input.request_id })));
  vi.spyOn(taskHandlingApi, 'request').mockResolvedValue(result(receipt()));
  vi.spyOn(crypto, 'randomUUID').mockReturnValue(requestId);
});
afterEach(() => { vi.restoreAllMocks(); useAuthStore.setState(original); });
function mount() {
  return renderHook(() => useTaskHandling(), { wrapper: ({ children }: { children: ReactNode }) =>
    <MemoryRouter initialEntries={['/alicloud?tab=task-handling&keep=source-one']}>{children}</MemoryRouter> });
}
async function select(view: ReturnType<typeof mount>) {
  await act(async () => { await view.result.current.load(); });
  await act(async () => { await view.result.current.select(eventId); });
}

it('does no network work on mount and submits one versioned operator annotation only on an explicit action', async () => {
  const view = mount();
  expect(taskHandlingApi.list).not.toHaveBeenCalled(); expect(taskHandlingApi.resolve).not.toHaveBeenCalled();
  await select(view);
  act(() => view.result.current.setDecision('external_action_reported'));
  await act(async () => { await view.result.current.submit('resolve'); await view.result.current.submit('resolve'); });
  expect(taskHandlingApi.resolve).toHaveBeenCalledTimes(1);
  expect(taskHandlingApi.resolve).toHaveBeenCalledWith(eventId, { request_id: requestId, expected_version: 0,
    expected_cloud_configuration_version: 7, expected_source_fingerprint: 'opaque-source-proof', decision: 'external_action_reported' });
  expect(view.result.current.pending?.id).toBe(requestId); expect(view.result.current.receipt?.requestId).toBe(requestId);
  expect(taskHandlingApi.archive).not.toHaveBeenCalled();
});

it('keeps the original body and UUID after a lost reply; even a receipt 404 cannot authorize another dispatch', async () => {
  vi.mocked(taskHandlingApi.resolve).mockRejectedValue(new TypeError('Connection interrupted'));
  vi.mocked(taskHandlingApi.request).mockRejectedValue(new ApiRequestError('Receipt absent', 404, 'not_found', false));
  const view = mount(); await select(view);
  act(() => view.result.current.setDecision('resolved_by_operator'));
  await act(async () => { await view.result.current.submit('resolve'); });
  const pending = view.result.current.pending;
  await act(async () => { await view.result.current.recover(); await view.result.current.newAction(); await view.result.current.submit('archive'); });
  expect(taskHandlingApi.request).toHaveBeenCalledWith(requestId);
  expect(view.result.current.pending).toEqual(pending); expect(view.result.current.decision).toBe('resolved_by_operator');
  expect(view.result.current.canStartNew).toBe(false); expect(taskHandlingApi.resolve).toHaveBeenCalledTimes(1);
  expect(taskHandlingApi.archive).not.toHaveBeenCalled(); expect(crypto.randomUUID).toHaveBeenCalledTimes(1);
});

it('a confirmed conflict permits a manual fresh read, without changing the draft or automatically retrying', async () => {
  vi.mocked(taskHandlingApi.resolve).mockRejectedValue(new ApiRequestError('Version changed', 409, 'conflict', false));
  const view = mount(); await select(view);
  act(() => view.result.current.setDecision('external_action_reported'));
  await act(async () => { await view.result.current.submit('resolve'); });
  expect(view.result.current.canStartNew).toBe(true);
  const list = vi.mocked(taskHandlingApi.list), detail = vi.mocked(taskHandlingApi.event);
  list.mockResolvedValue(result(page({ generation: 13 })));
  detail.mockResolvedValue(result(event({ currentSource: { ...event().currentSource, fingerprint: 'current-proof', cloudConfigurationVersion: 8 } })));
  await act(async () => { await view.result.current.newAction(); });
  expect(list).toHaveBeenCalledTimes(2); expect(detail).toHaveBeenCalledTimes(2);
  expect(view.result.current.pending).toBeUndefined(); expect(view.result.current.decision).toBe('external_action_reported');
  expect(taskHandlingApi.resolve).toHaveBeenCalledTimes(1); expect(crypto.randomUUID).toHaveBeenCalledTimes(1);
  await act(async () => { await view.result.current.submit('resolve'); });
  expect(vi.mocked(taskHandlingApi.resolve).mock.calls[1][1].expected_source_fingerprint).toBe('current-proof');
});

it('does not clear a known original request when either fresh read fails', async () => {
  const view = mount(); await select(view);
  await act(async () => { await view.result.current.submit('resolve'); });
  const pending = view.result.current.pending;
  vi.mocked(taskHandlingApi.event).mockRejectedValue(new Error('Source read failed'));
  await act(async () => { await view.result.current.newAction(); });
  expect(view.result.current.pending).toEqual(pending); expect(view.result.current.receipt?.requestId).toBe(requestId);
  expect(taskHandlingApi.resolve).toHaveBeenCalledTimes(1);
});

it('archives a removed source with null live proof and never tries to annotate it', async () => {
  vi.mocked(taskHandlingApi.event).mockResolvedValue(result(event({ allowedActions: ['read', 'archive'],
    currentSource: { ...event().currentSource, sourceExists: false, sourceGone: true, fingerprint: null, cloudConfigurationVersion: null } })));
  const view = mount(); await select(view);
  await act(async () => { await view.result.current.submit('resolve'); });
  expect(taskHandlingApi.resolve).not.toHaveBeenCalled();
  await act(async () => { await view.result.current.submit('archive'); });
  expect(taskHandlingApi.archive).toHaveBeenCalledWith({ request_id: requestId, expected_generation: 12,
    event_ids: [eventId], sources: [{ source_id: 'source-one', fingerprint: null }], expected_cloud_configuration_version: null });
});

it('refuses to send imprecise versions that JavaScript cannot safely represent', async () => {
  vi.mocked(taskHandlingApi.list).mockResolvedValue(result(page({ generation: Number.MAX_SAFE_INTEGER + 1 })));
  const view = mount(); await select(view);
  await act(async () => { await view.result.current.submit('archive'); });
  expect(taskHandlingApi.archive).not.toHaveBeenCalled(); expect(crypto.randomUUID).not.toHaveBeenCalled();
});

it('restores an earlier cursor page from the captured snapshot without another read or mutation', async () => {
  vi.mocked(taskHandlingApi.list).mockResolvedValueOnce(result(page({ nextCursor: 'signed-cursor-one' })))
    .mockResolvedValueOnce(result(page({ items: [], total: 1 })));
  const view = mount();
  await act(async () => { await view.result.current.load(); });
  await act(async () => { await view.result.current.load(true); });
  expect(taskHandlingApi.list).toHaveBeenLastCalledWith('signed-cursor-one');
  act(() => view.result.current.back());
  expect(view.result.current.page?.items[0].id).toBe(eventId); expect(taskHandlingApi.list).toHaveBeenCalledTimes(2);
  expect(taskHandlingApi.resolve).not.toHaveBeenCalled();
});

it('ignores a late page after A to B to A tenant/session changes', async () => {
  const slow = deferred<ApiResult<HandlingPage>>();
  vi.mocked(taskHandlingApi.list).mockReturnValue(slow.promise);
  const view = mount(); let read!: Promise<void>;
  act(() => { read = view.result.current.load(); });
  act(() => useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 }));
  act(() => useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 3 }));
  await act(async () => { slow.resolve(result(page())); await read; });
  expect(view.result.current.page).toBeUndefined(); expect(taskHandlingApi.resolve).not.toHaveBeenCalled();
});

it('uses the same selected time window for every cursor page and rejects an oversized window locally', async () => {
  vi.mocked(taskHandlingApi.list).mockResolvedValue(result(page({ nextCursor: 'signed-time-cursor' })));
  const view = mount();
  const window = { from: '2026-09-15T01:00:00Z', until: '2026-10-02T01:00:00Z' };
  await act(async () => { await view.result.current.load(false, window); });
  await act(async () => { await view.result.current.load(true); });
  expect(taskHandlingApi.list).toHaveBeenNthCalledWith(1, undefined, window);
  expect(taskHandlingApi.list).toHaveBeenNthCalledWith(2, 'signed-time-cursor', window);
  await act(async () => { await view.result.current.load(false, { ...window, from: '2026-08-01T01:00:00Z' }); });
  expect(taskHandlingApi.list).toHaveBeenCalledTimes(2);
  expect(view.result.current.error).toContain('30 days');
});
