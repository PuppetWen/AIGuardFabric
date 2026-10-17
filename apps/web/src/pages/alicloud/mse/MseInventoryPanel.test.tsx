import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ApiRequestError } from '@/api/transport';
import { mseInventoryApi } from '@/api/mseInventory';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import MseInventoryPanel from './MseInventoryPanel';
import { mseInventory, mseOperation, mseRequest, mseResult, mseService } from './mseFixtures';

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
  return render(<QueryClientProvider client={cache}><MemoryRouter><MseInventoryPanel /></MemoryRouter></QueryClientProvider>);
}
const syncButton = () => screen.getByRole('button', { name: /^(?:loading\s*)?Read complete services and publish inventory$/ });
const readButton = () => screen.getByRole('button', { name: /^(?:loading\s*)?Read original request receipt$/ });
function originalId() { return (screen.getByRole('textbox', { name: 'MSE original request UUID' }) as HTMLInputElement).value; }

it('requires live intent, keeps a failed UUID for GET recovery and starts a new UUID only after explicit preparation', async () => {
  vi.spyOn(mseInventoryApi, 'list').mockResolvedValue(mseResult(mseInventory({ mocked: false })));
  const first = deferred<Awaited<ReturnType<typeof mseInventoryApi.sync>>>();
  const sync = vi.spyOn(mseInventoryApi, 'sync').mockReturnValueOnce(first.promise)
    .mockImplementationOnce(async body => mseResult(mseOperation({ requestId: body.request_id, mocked: false, status: 'succeeded', published: true })));
  const receipt = vi.spyOn(mseInventoryApi, 'receipt').mockImplementation(async id => mseResult(mseOperation({ requestId: id, note: 'Original failed request' })));
  mount(); await screen.findByText('cn-hangzhou / instance-owned');
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
  vi.spyOn(mseInventoryApi, 'list').mockResolvedValue(mseResult(mseInventory()));
  const pending = deferred<Awaited<ReturnType<typeof mseInventoryApi.sync>>>();
  const oldRead = deferred<Awaited<ReturnType<typeof mseInventoryApi.receipt>>>();
  const sync = vi.spyOn(mseInventoryApi, 'sync').mockReturnValue(pending.promise);
  const receipt = vi.spyOn(mseInventoryApi, 'receipt').mockImplementationOnce(async id => mseResult(mseOperation({ requestId: id,
    status: 'running', finishedAt: null, canCancel: true, archivable: false, note: 'Active original request' }))).mockReturnValueOnce(oldRead.promise);
  const cancel = vi.spyOn(mseInventoryApi, 'cancel').mockImplementation(async id => mseResult(mseOperation({ requestId: id,
    status: 'cancelled', note: 'Explicit local cancellation' })));
  mount(); await screen.findByText('cn-hangzhou / instance-owned'); fireEvent.click(syncButton());
  const id = originalId(); expect(readButton()).toBeEnabled(); fireEvent.click(readButton());
  await screen.findByText('Active original request'); expect(receipt).toHaveBeenCalledWith(id);
  await waitFor(() => expect(readButton()).not.toHaveClass('ant-btn-loading')); fireEvent.click(readButton());
  fireEvent.click(screen.getByRole('button', { name: 'Cancel original request' }));
  fireEvent.click(await screen.findByRole('button', { name: 'OK' }));
  await screen.findByText('Explicit local cancellation'); expect(cancel).toHaveBeenCalledWith(id);
  await waitFor(() => expect(readButton()).not.toHaveClass('ant-btn-loading'));
  await act(async () => { oldRead.resolve(mseResult(mseOperation({ requestId: id, note: 'Obsolete GET receipt' }))); });
  expect(screen.queryByText('Obsolete GET receipt')).not.toBeInTheDocument();
  await act(async () => { pending.resolve(mseResult(mseOperation({ requestId: id, status: 'succeeded', published: true, note: 'Obsolete success' }))); });
  expect(screen.queryByText('Obsolete success')).not.toBeInTheDocument();
  expect(screen.getByText('Explicit local cancellation')).toBeInTheDocument(); expect(sync).toHaveBeenCalledOnce();
});

it('gives read-only users 50-row service pages, true zero versus unknown, asset links and the actual bilingual guide without POST', async () => {
  rights.delete('alicloud:write'); rights.delete('assets:write');
  vi.spyOn(mseInventoryApi, 'list').mockResolvedValue(mseResult(mseInventory({ inventoryAvailable: true, totalServices: 51,
    listingComplete: true, items: Array.from({ length: 51 }, (_, index) => mseService(index)) })));
  const sync = vi.spyOn(mseInventoryApi, 'sync'), cancel = vi.spyOn(mseInventoryApi, 'cancel'), archive = vi.spyOn(mseInventoryApi, 'archive');
  mount(); await screen.findByText('service-49');
  expect(screen.queryByText('service-50')).not.toBeInTheDocument(); expect(screen.getAllByText('0 / Unknown / Unknown')).toHaveLength(50);
  expect(screen.getAllByRole('link', { name: 'Open asset' })[0]).toHaveAttribute('href', '/assets/00000000-0000-4000-8000-000000000000');
  expect(syncButton()).toBeDisabled(); expect(screen.queryByRole('button', { name: 'Archive selected terminal receipts' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByTitle('2')); await screen.findByText('service-50');
  expect(screen.queryByText('service-49')).not.toBeInTheDocument();
  fireEvent.click(screen.getByText('MSE inventory, recovery and archive guide'));
  expect(await screen.findByText(/Provider credentials need read-only ListAnsServices/)).toBeInTheDocument();
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
  expect(screen.getByText(/未选择不是默认/)).toBeInTheDocument();
  expect(sync).not.toHaveBeenCalled(); expect(cancel).not.toHaveBeenCalled(); expect(archive).not.toHaveBeenCalled();
});

it('archives only explicitly selected terminal receipts on disabled configuration and retains a readable original tombstone', async () => {
  const failed = mseOperation({ current: false });
  const archived = mseOperation({ current: false, archived: true, archivable: false, archivedAt: '2026-09-30T00:03:00Z', status: 'archived', originalStatus: 'failed' });
  vi.spyOn(mseInventoryApi, 'list').mockResolvedValueOnce(mseResult(mseInventory({ configured: false, mocked: null,
    configurationVersion: null, operations: [failed] }))).mockResolvedValue(mseResult(mseInventory({ configured: false, operations: [], generation: 8, archivedCount: 1 })));
  vi.spyOn(mseInventoryApi, 'receipt').mockResolvedValueOnce(mseResult(failed)).mockResolvedValue(mseResult(archived));
  const archive = vi.spyOn(mseInventoryApi, 'archive').mockResolvedValue(mseResult({ generation: 8, archivedCount: 1, archivedRequestIds: [mseRequest] }));
  const sync = vi.spyOn(mseInventoryApi, 'sync'); mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Read original receipt' })); await screen.findByText('Owned receipt');
  const row = document.querySelector(`[data-row-key="${mseRequest}"]`)!;
  fireEvent.click(within(row as HTMLElement).getByRole('checkbox'));
  expect(archive).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: 'Archive selected terminal receipts' }));
  expect(await screen.findByText('Archive 1 selected terminal receipts?')).toBeInTheDocument(); expect(archive).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'OK' }));
  await screen.findByText(/Archive organizes the local terminal ledger only/);
  expect(archive).toHaveBeenCalledWith({ expected_generation: 7, request_ids: [mseRequest] });
  expect(originalId()).toBe(mseRequest); expect(sync).not.toHaveBeenCalled(); expect(syncButton()).toBeDisabled();
});

it('retains selection and evidence after archive409 and requires an explicit local refresh before reselection', async () => {
  const list = vi.spyOn(mseInventoryApi, 'list').mockResolvedValueOnce(mseResult(mseInventory({ operations: [mseOperation()] })))
    .mockResolvedValue(mseResult(mseInventory({ generation: 9, operations: [mseOperation()] })));
  const archive = vi.spyOn(mseInventoryApi, 'archive').mockRejectedValue(new ApiRequestError('Ledger changed409', 409, 'conflict', false));
  mount(); await screen.findByRole('button', { name: 'Read original receipt' });
  fireEvent.click(within(document.querySelector(`[data-row-key="${mseRequest}"]`)! as HTMLElement).getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Archive selected terminal receipts' }));
  fireEvent.click(await screen.findByRole('button', { name: 'OK' })); await screen.findByText('Ledger changed409');
  expect(list).toHaveBeenCalledOnce(); expect(archive).toHaveBeenCalledOnce();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh local inventory and receipts' }));
  await screen.findByText(/Ledger generation 9/); expect(screen.getByRole('button', { name: 'Archive selected terminal receipts' })).toBeDisabled();
  expect(screen.queryByText('Ledger changed409')).not.toBeInTheDocument();
  expect(archive).toHaveBeenCalledOnce();
});

it('aborts and discards an older tenant inventory load instead of showing it under the new tenant', async () => {
  const old = deferred<Awaited<ReturnType<typeof mseInventoryApi.list>>>();
  const list = vi.spyOn(mseInventoryApi, 'list').mockReturnValueOnce(old.promise)
    .mockResolvedValue(mseResult(mseInventory({ instanceId: 'new-tenant-instance' })));
  mount(); await waitFor(() => expect(list).toHaveBeenCalledOnce());
  const signal = list.mock.calls[0][0];
  await act(async () => { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 101 }); });
  await screen.findByText('cn-hangzhou / new-tenant-instance'); expect(signal?.aborted).toBe(true);
  await act(async () => { old.resolve(mseResult(mseInventory({ instanceId: 'obsolete-private-instance' }))); });
  expect(screen.queryByText(/obsolete-private-instance/)).not.toBeInTheDocument();
});

it('clears an old session receipt and rejects its late result after a same-tenant new login', async () => {
  vi.spyOn(mseInventoryApi, 'list').mockResolvedValue(mseResult(mseInventory()));
  const old = deferred<Awaited<ReturnType<typeof mseInventoryApi.receipt>>>();
  vi.spyOn(mseInventoryApi, 'receipt').mockReturnValue(old.promise);
  const sync = vi.spyOn(mseInventoryApi, 'sync'); mount(); await screen.findByText('cn-hangzhou / instance-owned');
  fireEvent.change(screen.getByRole('textbox', { name: 'MSE original request UUID' }), { target: { value: mseRequest } });
  fireEvent.click(readButton());
  await act(async () => { useAuthStore.setState({ sessionGeneration: 101 }); });
  await screen.findByText('cn-hangzhou / instance-owned'); expect(originalId()).toBe('');
  await act(async () => { old.resolve(mseResult(mseOperation({ note: 'Obsolete session receipt' }))); });
  expect(screen.queryByText('Obsolete session receipt')).not.toBeInTheDocument(); expect(sync).not.toHaveBeenCalled();
});
