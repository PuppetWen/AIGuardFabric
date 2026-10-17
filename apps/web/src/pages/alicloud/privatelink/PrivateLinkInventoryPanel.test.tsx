import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ApiRequestError } from '@/api/transport';
import { privatelinkInventoryApi } from '@/api/privatelinkInventory';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import PrivateLinkInventoryPanel from './PrivateLinkInventoryPanel';
import { privatelinkEndpoint, privatelinkGraph, privatelinkInventory, privatelinkOperation, privatelinkRequest, privatelinkResult } from './privatelinkFixtures';

const rights = new Set<string>();
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: () => ({ has: (permission: string) => rights.has(permission), isLoading: false }) }));
const original = useAuthStore.getState(), caches: QueryClient[] = [];
function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (reason: Error) => void;
  const promise = new Promise<T>((accept, fail) => { resolve = accept; reject = fail; });
  return { promise, resolve, reject };
}
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  rights.clear(); ['alicloud:read','alicloud:write','assets:write','assets:read'].forEach(right => rights.add(right));
  useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 100 });
});
afterEach(async () => {
  cleanup(); caches.forEach(cache => cache.clear()); caches.length = 0;
  vi.restoreAllMocks(); useAuthStore.setState(original);
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});
function mount() {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } }); caches.push(cache);
  return render(<QueryClientProvider client={cache}><MemoryRouter><PrivateLinkInventoryPanel /></MemoryRouter></QueryClientProvider>);
}
const syncButton = () => screen.getByRole('button', { name: /^(?:loading\s*)?Read endpoint and publish observations$/ });
const readButton = () => screen.getByRole('button', { name: /^(?:loading\s*)?Read original request receipt$/ });
function originalId() { return (screen.getByRole('textbox', { name: 'PrivateLink original request UUID' }) as HTMLInputElement).value; }

it('requires live intent, keeps a failed UUID for GET recovery and starts a new UUID only after explicit preparation', async () => {
  vi.spyOn(privatelinkInventoryApi, 'list').mockResolvedValue(privatelinkResult(privatelinkInventory({ mocked: false })));
  const first = deferred<Awaited<ReturnType<typeof privatelinkInventoryApi.sync>>>();
  const sync = vi.spyOn(privatelinkInventoryApi, 'sync').mockReturnValueOnce(first.promise)
    .mockImplementationOnce(async body => privatelinkResult(privatelinkOperation({ requestId: body.request_id, mocked: false, status: 'succeeded', published: true })));
  const receipt = vi.spyOn(privatelinkInventoryApi, 'receipt').mockImplementation(async id => privatelinkResult(privatelinkOperation({ requestId: id, note: 'Original failed request' })));
  mount(); await screen.findByText('cn-hangzhou / ep-owned');
  expect(syncButton()).toBeDisabled(); fireEvent.click(syncButton()); expect(sync).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('checkbox', { name: /Confirm live read-only/ }));
  fireEvent.click(syncButton()); fireEvent.click(syncButton());
  expect(sync).toHaveBeenCalledTimes(1); const id = originalId(); expect(id).toMatch(/^[0-9a-f-]{36}$/);
  await act(async () => { first.reject(new Error('Owned listing failed')); });
  expect(await screen.findByText('Owned listing failed')).toBeInTheDocument();
  expect(originalId()).toBe(id); expect(syncButton()).toBeDisabled();
  fireEvent.click(readButton()); await screen.findByText('Original failed request');
  expect(receipt).toHaveBeenCalledWith(id); expect(sync).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Prepare new inventory' }));
  expect(originalId()).toBe(''); expect(syncButton()).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox', { name: /Confirm live read-only/ })); fireEvent.click(syncButton());
  await waitFor(() => expect(sync).toHaveBeenCalledTimes(2));
  expect(sync.mock.calls[1][0].request_id).not.toBe(id);
  expect(sync.mock.calls[1][0]).toMatchObject({ configuration_version: 4, confirm_live: true });
});

it('allows GET and explicit cancellation while a long inventory is pending; its late response cannot replace cancellation', async () => {
  vi.spyOn(privatelinkInventoryApi, 'list').mockResolvedValue(privatelinkResult(privatelinkInventory()));
  const pending = deferred<Awaited<ReturnType<typeof privatelinkInventoryApi.sync>>>();
  const oldRead = deferred<Awaited<ReturnType<typeof privatelinkInventoryApi.receipt>>>();
  const sync = vi.spyOn(privatelinkInventoryApi, 'sync').mockReturnValue(pending.promise);
  const receipt = vi.spyOn(privatelinkInventoryApi, 'receipt').mockImplementationOnce(async id => privatelinkResult(privatelinkOperation({ requestId: id,
    status: 'running', finishedAt: null, canCancel: true, archivable: false, note: 'Active original request' }))).mockReturnValueOnce(oldRead.promise);
  const cancel = vi.spyOn(privatelinkInventoryApi, 'cancel').mockImplementation(async id => privatelinkResult(privatelinkOperation({ requestId: id,
    status: 'cancelled', note: 'Explicit local cancellation' })));
  mount(); await screen.findByText('cn-hangzhou / ep-owned'); fireEvent.click(syncButton());
  const id = originalId(); expect(readButton()).toBeEnabled(); fireEvent.click(readButton());
  await screen.findByText('Active original request'); expect(receipt).toHaveBeenCalledWith(id);
  await waitFor(() => expect(readButton()).not.toHaveClass('ant-btn-loading')); fireEvent.click(readButton());
  fireEvent.click(screen.getByRole('button', { name: 'Cancel original request' }));
  fireEvent.click(await screen.findByRole('button', { name: 'OK' }));
  await screen.findByText('Explicit local cancellation'); expect(cancel).toHaveBeenCalledWith(id);
  await waitFor(() => expect(readButton()).not.toHaveClass('ant-btn-loading'));
  await act(async () => { oldRead.resolve(privatelinkResult(privatelinkOperation({ requestId: id, note: 'Obsolete GET receipt' }))); });
  expect(screen.queryByText('Obsolete GET receipt')).not.toBeInTheDocument();
  await act(async () => { pending.resolve(privatelinkResult(privatelinkOperation({ requestId: id, status: 'succeeded', published: true, note: 'Obsolete success' }))); });
  expect(screen.queryByText('Obsolete success')).not.toBeInTheDocument();
  expect(screen.getByText('Explicit local cancellation')).toBeInTheDocument(); expect(sync).toHaveBeenCalledOnce();
});

it('archives only explicitly selected terminal receipts on disabled configuration and retains a readable original tombstone', async () => {
  const failed = privatelinkOperation({ current: false });
  const archived = privatelinkOperation({ current: false, archived: true, archivable: false, archivedAt: '2026-09-30T00:03:00Z', status: 'archived', originalStatus: 'failed' });
  vi.spyOn(privatelinkInventoryApi, 'list').mockResolvedValueOnce(privatelinkResult(privatelinkInventory({ configured: false, mocked: null,
    configurationVersion: null, operations: [failed] }))).mockResolvedValue(privatelinkResult(privatelinkInventory({ configured: false, operations: [], generation: 8, archivedCount: 1 })));
  vi.spyOn(privatelinkInventoryApi, 'receipt').mockResolvedValueOnce(privatelinkResult(failed)).mockResolvedValue(privatelinkResult(archived));
  const archive = vi.spyOn(privatelinkInventoryApi, 'archive').mockResolvedValue(privatelinkResult({ generation: 8, archivedCount: 1, archivedRequestIds: [privatelinkRequest] }));
  const sync = vi.spyOn(privatelinkInventoryApi, 'sync'); mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Read original receipt' })); await screen.findByText('Owned receipt');
  const row = document.querySelector(`[data-row-key="${privatelinkRequest}"]`)!;
  fireEvent.click(within(row as HTMLElement).getByRole('checkbox'));
  expect(archive).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: 'Archive selected terminal receipts' }));
  expect(await screen.findByText('Archive 1 selected terminal receipts?')).toBeInTheDocument(); expect(archive).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'OK' }));
  await screen.findByText(/Archive organizes the local terminal ledger only/);
  expect(archive).toHaveBeenCalledWith({ expected_generation: 7, request_ids: [privatelinkRequest] });
  expect(originalId()).toBe(privatelinkRequest); expect(sync).not.toHaveBeenCalled(); expect(syncButton()).toBeDisabled();
});

it('retains selection and evidence after archive409 and requires an explicit local refresh before reselection', async () => {
  const list = vi.spyOn(privatelinkInventoryApi, 'list').mockResolvedValueOnce(privatelinkResult(privatelinkInventory({ operations: [privatelinkOperation()] })))
    .mockResolvedValue(privatelinkResult(privatelinkInventory({ generation: 9, operations: [privatelinkOperation()] })));
  const archive = vi.spyOn(privatelinkInventoryApi, 'archive').mockRejectedValue(new ApiRequestError('Ledger changed409', 409, 'conflict', false));
  mount(); await screen.findByRole('button', { name: 'Read original receipt' });
  fireEvent.click(within(document.querySelector(`[data-row-key="${privatelinkRequest}"]`)! as HTMLElement).getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Archive selected terminal receipts' }));
  fireEvent.click(await screen.findByRole('button', { name: 'OK' })); await screen.findByText('Ledger changed409');
  expect(list).toHaveBeenCalledOnce(); expect(archive).toHaveBeenCalledOnce();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh local observations and receipts' }));
  await screen.findByText(/Ledger generation 9/); expect(screen.getByRole('button', { name: 'Archive selected terminal receipts' })).toBeDisabled();
  expect(screen.queryByText('Ledger changed409')).not.toBeInTheDocument();
  expect(archive).toHaveBeenCalledOnce();
});

it('aborts and discards an older tenant inventory load instead of showing it under the new tenant', async () => {
  const old = deferred<Awaited<ReturnType<typeof privatelinkInventoryApi.list>>>();
  const list = vi.spyOn(privatelinkInventoryApi, 'list').mockReturnValueOnce(old.promise)
    .mockResolvedValue(privatelinkResult(privatelinkInventory({ endpointId: 'new-tenant-endpoint' })));
  mount(); await waitFor(() => expect(list).toHaveBeenCalledOnce());
  const signal = list.mock.calls[0][0];
  await act(async () => { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 101 }); });
  await screen.findByText('cn-hangzhou / new-tenant-endpoint'); expect(signal?.aborted).toBe(true);
  await act(async () => { old.resolve(privatelinkResult(privatelinkInventory({ endpointId: 'obsolete-private-endpoint' }))); });
  expect(screen.queryByText(/obsolete-private-endpoint/)).not.toBeInTheDocument();
});

it('clears an old session receipt and rejects its late result after a same-tenant new login', async () => {
  vi.spyOn(privatelinkInventoryApi, 'list').mockResolvedValue(privatelinkResult(privatelinkInventory()));
  const old = deferred<Awaited<ReturnType<typeof privatelinkInventoryApi.receipt>>>();
  vi.spyOn(privatelinkInventoryApi, 'receipt').mockReturnValue(old.promise);
  const sync = vi.spyOn(privatelinkInventoryApi, 'sync'); mount(); await screen.findByText('cn-hangzhou / ep-owned');
  fireEvent.change(screen.getByRole('textbox', { name: 'PrivateLink original request UUID' }), { target: { value: privatelinkRequest } });
  fireEvent.click(readButton());
  await act(async () => { useAuthStore.setState({ sessionGeneration: 101 }); });
  await screen.findByText('cn-hangzhou / ep-owned'); expect(originalId()).toBe('');
  await act(async () => { old.resolve(privatelinkResult(privatelinkOperation({ note: 'Obsolete session receipt' }))); });
  expect(screen.queryByText('Obsolete session receipt')).not.toBeInTheDocument(); expect(sync).not.toHaveBeenCalled();
});

it('discards a late inventory write result after switching tenant and clears its original request', async () => {
  vi.spyOn(privatelinkInventoryApi, 'list').mockResolvedValue(privatelinkResult(privatelinkInventory()));
  const old = deferred<Awaited<ReturnType<typeof privatelinkInventoryApi.sync>>>();
  const sync = vi.spyOn(privatelinkInventoryApi, 'sync').mockReturnValue(old.promise);
  mount(); await screen.findByText('cn-hangzhou / ep-owned'); fireEvent.click(syncButton());
  const id = originalId(); expect(sync).toHaveBeenCalledOnce();
  await act(async () => { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 101 }); });
  await screen.findByText('cn-hangzhou / ep-owned'); expect(originalId()).toBe('');
  await act(async () => { old.resolve(privatelinkResult(privatelinkOperation({ requestId: id, status: 'succeeded', published: true, note: 'Obsolete tenant publication' }))); });
  expect(screen.queryByText('Obsolete tenant publication')).not.toBeInTheDocument(); expect(originalId()).toBe('');
  expect(sync).toHaveBeenCalledOnce();
});

it('lets read-only users inspect actual cross-region references, known zero versus unknown and the bilingual guide without writes', async () => {
  rights.delete('alicloud:write'); rights.delete('assets:write');
  vi.spyOn(privatelinkInventoryApi, 'list').mockResolvedValue(privatelinkResult(privatelinkInventory({ topologyAvailable: true,
    checkedAt: '2026-10-01T00:01:00Z', pagesRead: 2, listingComplete: true, endpoint: privatelinkEndpoint(), graph: privatelinkGraph() })));
  const sync = vi.spyOn(privatelinkInventoryApi, 'sync'), cancel = vi.spyOn(privatelinkInventoryApi, 'cancel'), archive = vi.spyOn(privatelinkInventoryApi, 'archive');
  mount(); await screen.findByRole('heading', { name: 'Zones · 0' });
  expect(screen.getByRole('heading', { name: 'Security groups · Unknown' })).toBeInTheDocument();
  expect(screen.getByText('Security-group list unavailable; this is not zero.')).toBeInTheDocument();
  expect(screen.getByText('Active / Connected / Unknown')).toBeInTheDocument();
  expect(screen.getByText(/Cloud status and a DNS name do not establish routes/)).toBeInTheDocument();
  expect(syncButton()).toBeDisabled(); expect(screen.queryByRole('button', { name: 'Archive selected terminal receipts' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByText('PrivateLink inventory, recovery and archive guide'));
  expect(screen.getByText(/Provider credentials need read permissions for GetVpcEndpointAttribute/)).toBeInTheDocument();
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
  expect(screen.getByText(/端点 ID 未填写不会自动选目标/)).toBeInTheDocument();
  expect(sync).not.toHaveBeenCalled(); expect(cancel).not.toHaveBeenCalled(); expect(archive).not.toHaveBeenCalled();
});

it('does not archive an expired nonterminal request before its explicit cancellation', async () => {
  const interrupted = privatelinkOperation({ status: 'interrupted', canCancel: true, archivable: false, finishedAt: null });
  vi.spyOn(privatelinkInventoryApi, 'list').mockResolvedValue(privatelinkResult(privatelinkInventory({ operations: [interrupted] })));
  vi.spyOn(privatelinkInventoryApi, 'receipt').mockResolvedValue(privatelinkResult(interrupted));
  const archive = vi.spyOn(privatelinkInventoryApi, 'archive'), cancel = vi.spyOn(privatelinkInventoryApi, 'cancel');
  mount(); fireEvent.click(await screen.findByRole('button', { name: 'Read original receipt' }));
  await screen.findByText(/The lease expired but the stored record is not terminal/);
  const row = document.querySelector(`[data-row-key="${privatelinkRequest}"]`)! as HTMLElement;
  expect(within(row).getByRole('checkbox')).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Archive selected terminal receipts' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Cancel original request' })).toBeEnabled();
  expect(archive).not.toHaveBeenCalled(); expect(cancel).not.toHaveBeenCalled();
});
