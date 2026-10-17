import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { useEffect } from 'react';
import { ConfigProvider } from 'antd';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { multiTargetApi, type MultiRecent, type MultiRun } from '@/api/redteamMultiTarget';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import { RecentRuns } from './RecentRuns';
import { useMultiTarget } from './useMultiTarget';
const original = useAuthStore.getState();
const id = '10000000-0000-4000-8000-000000000001';
const row: MultiRun = { requestId: id, status: 'completed', completionState: 'complete', generation: 5, archivedAt: null, originalStatus: null,
  sourceCurrent: true, evidence: [], findingIds: [], auditId: id, defensePassed: null, localFixture: true, externalDefenseVerified: false };
const recent: MultiRecent = { items: [{ requestId: id, status: 'completed', completionState: 'complete', generation: 5, archived: false, originalStatus: null }], total: 1, offset: 0, limit: 20, truncated: false, completeHistory: false };
let model!: ReturnType<typeof useMultiTarget>;
function Harness() {
  const current = useMultiTarget();
  useEffect(() => { model = current; }, [current]);
  return <ConfigProvider theme={{ token: { motion: false } }}><RecentRuns model={current} canExecute zh={false} /></ConfigProvider>;
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
beforeEach(() => {
  useAuthStore.setState({ tenant: { id: 'a', slug: 'a' } as Tenant, sessionGeneration: 1 });
  vi.spyOn(multiTargetApi, 'profiles').mockResolvedValue({ items: [] });
  vi.spyOn(multiTargetApi, 'recent').mockResolvedValue(recent);
  vi.spyOn(multiTargetApi, 'get').mockImplementation(async requestId => ({ ...row, requestId }));
  vi.spyOn(multiTargetApi, 'execute').mockRejectedValue(new Error('unresolved'));
  vi.spyOn(multiTargetApi, 'preview').mockResolvedValue({ topologySha256: 'a'.repeat(64), topology: {}, requiresDatabase: true });
  vi.spyOn(multiTargetApi, 'archive').mockImplementation(async requestId => ({ ...row, requestId, status: 'archived', generation: 6, originalStatus: 'completed' }));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); useAuthStore.setState(original); });
it('explicit recent GET lists only returned UUIDs and selecting one performs GET without any dispatch', async () => {
  render(<Harness />); expect(multiTargetApi.recent).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Read my recent UUIDs' }));
  await waitFor(() => expect(multiTargetApi.recent).toHaveBeenCalledWith(0, expect.any(AbortSignal)));
  fireEvent.click(await screen.findByRole('button', { name: id + ' · completed · g5' }));
  await waitFor(() => expect(multiTargetApi.get).toHaveBeenCalledWith(id, expect.any(AbortSignal)));
  await waitFor(() => expect(model.receipt?.requestId).toBe(id));
  expect(multiTargetApi.execute).not.toHaveBeenCalled();
  expect(multiTargetApi.archive).not.toHaveBeenCalled();
});
it('a historical recent B complete cannot release a newly held unknown A', async () => {
  render(<Harness />);
  await act(async () => { await model.review([]); });
  expect(model.preview?.topologySha256).toBe('a'.repeat(64));
  await act(async () => { await model.execute(true); });
  expect(multiTargetApi.execute).toHaveBeenCalledTimes(1);
  const a = vi.mocked(multiTargetApi.execute).mock.calls[0][0].request_id;
  expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  expect(model.requestId).toBe(a);
  expect(a).not.toBe(id);
  expect(model.attempted).toBe(true);
  expect(model.canNewIntent).toBe(false);
  await act(async () => { await model.recentRuns(); await model.readOriginal(id); });
  expect(model.receipt?.requestId).toBe(id); expect(model.canNewIntent).toBe(false);
  act(() => model.newIntent()); expect(model.attempted).toBe(true);
  await act(async () => { await model.execute(true); });
  expect(multiTargetApi.execute).toHaveBeenCalledTimes(1);
});
it('archive confirmation captures reviewed generation before a newer GET and never retries 409', async () => {
  render(<Harness />);
  await act(async () => { await model.readOriginal(id); });
  fireEvent.click(screen.getByRole('button', { name: 'Archive reviewed run' }));
  await screen.findByRole('tooltip');
  vi.mocked(multiTargetApi.get).mockResolvedValue({ ...row, generation: 7 });
  await act(async () => { await model.readOriginal(id); });
  vi.mocked(multiTargetApi.archive).mockRejectedValue(new Error('409'));
  fireEvent.click(within(screen.getByRole('tooltip')).getByRole('button', { name: /^(OK|确定)$/ }));
  await waitFor(() => expect(multiTargetApi.archive).toHaveBeenCalledWith(id, 5, expect.any(AbortSignal)));
  expect(model.receipt?.generation).toBe(7); expect(multiTargetApi.archive).toHaveBeenCalledTimes(1);
});
it('late owner recent response is aborted and dropped through tenant A B A', async () => {
  const held = deferred<MultiRecent>(); vi.mocked(multiTargetApi.recent).mockReturnValue(held.promise);
  render(<Harness />); let pending!: Promise<void>; act(() => { pending = model.recentRuns(); });
  const signal = vi.mocked(multiTargetApi.recent).mock.calls[0][1];
  act(() => { useAuthStore.setState({ tenant: { id: 'b', slug: 'b' } as Tenant }); useAuthStore.setState({ tenant: { id: 'a', slug: 'a' } as Tenant }); });
  await act(async () => { held.resolve(recent); await pending; });
  expect(signal?.aborted).toBe(true); expect(model.recent).toBeNull(); expect(multiTargetApi.execute).not.toHaveBeenCalled();
});
