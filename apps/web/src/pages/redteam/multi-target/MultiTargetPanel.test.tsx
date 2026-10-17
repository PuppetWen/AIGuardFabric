import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react';
import { ConfigProvider } from 'antd';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { multiTargetApi, type MultiRun, type MultiSelection } from '@/api/redteamMultiTarget';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import { MultiTargetPanel } from './MultiTargetPanel';
import { useMultiTarget } from './useMultiTarget';
const original = useAuthStore.getState();
const ids = ['10000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000003'];
const request = '20000000-0000-4000-8000-000000000001';
const targets: MultiSelection[] = ids.map((id, at) => ({ kind: at === 1 ? 'mcp-http' : 'agent-http', profile_id: id, expected_version: 7 }));
const topology = { topologySha256: 'a'.repeat(64), requiresDatabase: true, topology: { steps: [0, 1, 2], rawBodiesStored: false } };
const receipt: MultiRun = { requestId: request, status: 'completed', generation:5,archivedAt:null,originalStatus:null,completionState: 'complete', sourceCurrent: true, evidence: [], findingIds: [], auditId: request, defensePassed: true, localFixture: true, externalDefenseVerified: false };
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
beforeEach(async () => {
  await i18n.changeLanguage('en-US'); useAuthStore.setState({ tenant: { id: 'tenant-a', slug: 'a' } as Tenant, sessionGeneration: 1 });
  vi.spyOn(multiTargetApi, 'profiles').mockImplementation(async kind => ({ items: ids.filter((_, at) => kind === 'mcp' ? at === 1 : at !== 1)
    .map(id => ({ id, assetId: `${id}-asset`, name: `Registered ${id}`, enabled: true, version: 7 })) }));
  vi.spyOn(multiTargetApi, 'preview').mockResolvedValue(topology);
  vi.spyOn(multiTargetApi, 'execute').mockImplementation(async body => ({ ...receipt, requestId: body.request_id }));
  vi.spyOn(multiTargetApi, 'get').mockImplementation(async id => ({ ...receipt, requestId: id }));
  vi.spyOn(multiTargetApi, 'local').mockImplementation(async id => ({ ...receipt, requestId: id }));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); useAuthStore.setState(original); });
async function mountHook() { const hook = renderHook(useMultiTarget); await waitFor(() => expect(hook.result.current.agents).toHaveLength(2)); return hook; }
it('loads real inventory without automatic selection, preview, execution or receipt reads', async () => {
  render(<ConfigProvider theme={{ token: { motion: false } }}><MultiTargetPanel canExecute /></ConfigProvider>);
  await waitFor(() => expect(multiTargetApi.profiles).toHaveBeenCalledTimes(2));
  expect(screen.getByRole('combobox', { name: 'Agent A' })).toHaveValue('');
  expect(screen.getByRole('button', { name: 'Preview fixed topology' })).toBeDisabled();
  expect(multiTargetApi.preview).not.toHaveBeenCalled(); expect(multiTargetApi.execute).not.toHaveBeenCalled(); expect(multiTargetApi.get).not.toHaveBeenCalled();
});
it('keeps the reviewed exact revisions and one UUID after an unknown response; GET 404 never unlocks resend', async () => {
  vi.mocked(multiTargetApi.execute).mockRejectedValue(new Error('unknown')); vi.mocked(multiTargetApi.get).mockRejectedValue(new Error('404'));
  const hook = await mountHook(); await act(async () => { await hook.result.current.review(targets); });
  await act(async () => { await hook.result.current.execute(true); });
  const id = hook.result.current.requestId; expect(id).toMatch(/^[0-9a-f-]{36}$/i); expect(hook.result.current.attempted).toBe(true);
  expect(multiTargetApi.execute).toHaveBeenCalledWith(expect.objectContaining({ request_id: id, targets, reviewed_topology_sha256: topology.topologySha256, confirm_live: true }), expect.any(AbortSignal));
  await act(async () => { await hook.result.current.read(); await hook.result.current.execute(true); });
  expect(multiTargetApi.get).toHaveBeenCalledWith(id, expect.any(AbortSignal)); expect(multiTargetApi.execute).toHaveBeenCalledTimes(1);
  expect(hook.result.current.requestId).toBe(id); expect(hook.result.current.preview).toEqual(topology);
});
it('allows local cancellation during a held execute and rejects its later receipt', async () => {
  const held = deferred<MultiRun>(); vi.mocked(multiTargetApi.execute).mockReturnValue(held.promise);
  vi.mocked(multiTargetApi.local).mockImplementation(async id => ({ ...receipt, requestId: id, status: 'cancelled' }));
  const hook = await mountHook(); await act(async () => { await hook.result.current.review(targets); });
  let execution!: Promise<void>; act(() => { execution = hook.result.current.execute(true); });
  expect(hook.result.current.busy).toBe(true); const id = hook.result.current.requestId;
  await act(async () => { await hook.result.current.local('cancel'); });
  expect(multiTargetApi.local).toHaveBeenCalledWith(id, 'cancel', expect.any(AbortSignal));
  expect(hook.result.current.receipt?.status).toBe('cancelled');
  await act(async () => { held.resolve({ ...receipt, requestId: id }); await execution; }); expect(hook.result.current.receipt?.status).toBe('cancelled');
});
it('an explicit original GET outranks a late execute response without issuing another POST', async () => {
  const held = deferred<MultiRun>(); vi.mocked(multiTargetApi.execute).mockReturnValue(held.promise);
  vi.mocked(multiTargetApi.get).mockImplementation(async id => ({ ...receipt, requestId: id, sourceCurrent: false }));
  const hook = await mountHook(); await act(async () => { await hook.result.current.review(targets); });
  let execution!: Promise<void>; act(() => { execution = hook.result.current.execute(true); });
  await act(async () => { await hook.result.current.read(); });
  await act(async () => { held.resolve({ ...receipt, requestId: hook.result.current.requestId }); await execution; });
  expect(hook.result.current.receipt?.sourceCurrent).toBe(false); expect(multiTargetApi.execute).toHaveBeenCalledTimes(1);
});
it('an old complete GET cannot unlock a newly submitted unknown UUID, even after its original GET returns 404', async () => {
  const hook = await mountHook(); act(() => { hook.result.current.setRequestId(request); });
  await act(async () => { await hook.result.current.read(); }); expect(hook.result.current.receipt?.requestId).toBe(request);
  vi.mocked(multiTargetApi.execute).mockRejectedValue(new Error('unknown'));
  await act(async () => { await hook.result.current.review(targets); });
  await act(async () => { await hook.result.current.execute(true); }); const id = hook.result.current.requestId;
  expect(hook.result.current.receipt).toBeNull(); expect(hook.result.current.canNewIntent).toBe(false);
  act(() => { hook.result.current.newIntent(); });
  vi.mocked(multiTargetApi.get).mockRejectedValue(new Error('404')); await act(async () => { await hook.result.current.read(); });
  act(() => { hook.result.current.newIntent(); }); await act(async () => { await hook.result.current.execute(true); });
  expect(hook.result.current.requestId).toBe(id); expect(hook.result.current.attempted).toBe(true); expect(multiTargetApi.execute).toHaveBeenCalledTimes(1);
});
it('a historical B receipt cannot release held A, and an older A execute cannot outrank an explicit A receipt', async () => {
  const held = deferred<MultiRun>(); vi.mocked(multiTargetApi.execute).mockReturnValue(held.promise);
  const hook = await mountHook(); await act(async () => { await hook.result.current.review(targets); });
  let execution!: Promise<void>; act(() => { execution = hook.result.current.execute(true); }); const a = hook.result.current.requestId;
  act(() => { hook.result.current.setRequestId(request); }); await act(async () => { await hook.result.current.read(); });
  expect(hook.result.current.receipt?.requestId).toBe(request); expect(hook.result.current.canNewIntent).toBe(false);
  act(() => { hook.result.current.newIntent(); }); expect(hook.result.current.attempted).toBe(true);
  act(() => { hook.result.current.setRequestId(a); });
  vi.mocked(multiTargetApi.get).mockResolvedValue({ ...receipt, requestId: a, completionState: 'pending_audit' });
  await act(async () => { await hook.result.current.read(); });
  await act(async () => { held.resolve({ ...receipt, requestId: a }); await execution; });
  expect(hook.result.current.receipt?.completionState).toBe('pending_audit'); expect(hook.result.current.canNewIntent).toBe(false);
  vi.mocked(multiTargetApi.get).mockResolvedValue({ ...receipt, requestId: a }); await act(async () => { await hook.result.current.read(); });
  expect(hook.result.current.canNewIntent).toBe(true); act(() => { hook.result.current.newIntent(); });
  expect(hook.result.current.attempted).toBe(false); expect(multiTargetApi.execute).toHaveBeenCalledTimes(1);
});
it('mismatched execute, GET and local response identities never unlock the current intent', async () => {
  vi.mocked(multiTargetApi.execute).mockResolvedValue(receipt); vi.mocked(multiTargetApi.get).mockResolvedValue(receipt); vi.mocked(multiTargetApi.local).mockResolvedValue(receipt);
  const hook = await mountHook(); await act(async () => { await hook.result.current.review(targets); });
  await act(async () => { await hook.result.current.execute(true); }); const id = hook.result.current.requestId;
  await act(async () => { await hook.result.current.read(); await hook.result.current.local('recover'); });
  expect(hook.result.current.receipt).toBeNull(); expect(hook.result.current.canNewIntent).toBe(false);
  act(() => { hook.result.current.newIntent(); }); expect(hook.result.current.requestId).toBe(id); expect(hook.result.current.attempted).toBe(true);
  expect(multiTargetApi.execute).toHaveBeenCalledTimes(1);
});
it('drops delayed preview through A to B to A and aborts the original request', async () => {
  const held = deferred<typeof topology>(); vi.mocked(multiTargetApi.preview).mockReturnValue(held.promise);
  const hook = await mountHook(); let review!: Promise<void>; act(() => { review = hook.result.current.review(targets); });
  const signal = vi.mocked(multiTargetApi.preview).mock.calls[0][1];
  act(() => { useAuthStore.setState({ tenant: { id: 'tenant-b', slug: 'b' } as Tenant }); useAuthStore.setState({ tenant: { id: 'tenant-a', slug: 'a' } as Tenant }); });
  await act(async () => { held.resolve(topology); await review; });
  expect(signal?.aborted).toBe(true); expect(hook.result.current.preview).toBeNull(); expect(multiTargetApi.execute).not.toHaveBeenCalled();
});
it('manual UUID input performs only GET; local recovery never sends the original execute body', async () => {
  function Harness() { const state = useMultiTarget(); return <><input aria-label="manual" value={state.requestId} onChange={event => state.setRequestId(event.target.value)} />
    <button onClick={() => void state.read()}>Read</button><button onClick={() => void state.local('recover')}>Recover</button></>; }
  render(<Harness />); fireEvent.change(screen.getByLabelText('manual'), { target: { value: request } }); fireEvent.click(screen.getByRole('button', { name: 'Read' }));
  await waitFor(() => expect(multiTargetApi.get).toHaveBeenCalledWith(request, expect.any(AbortSignal))); fireEvent.click(screen.getByRole('button', { name: 'Recover' }));
  await waitFor(() => expect(multiTargetApi.local).toHaveBeenCalledWith(request, 'recover', expect.any(AbortSignal)));
  expect(multiTargetApi.execute).not.toHaveBeenCalled(); expect(multiTargetApi.preview).not.toHaveBeenCalled();
});
