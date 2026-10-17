import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cloudApi, type CloudConfig } from '@/api/cloud';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import CloudEditor from './CloudEditor';

const rights = new Set<string>();
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: () => ({ has: (permission: string) => rights.has(permission), isLoading: false }) }));
vi.mock('./CloudOperations', () => ({ default: () => null }));
vi.mock('./CloudInventory', () => ({ CloudInventory: () => null }));
vi.mock('./mse/MseInventoryPanel', () => ({ default: () => <div>MSE read-only inventory entry</div> }));
vi.mock('./mse/MseInventoryGuide', () => ({ default: () => null }));
const original = useAuthStore.getState();
const result = <T,>(data: T) => ({ data, meta: { source: 'live' as const, elapsedMs: 1, at: Date.now() } });
const snapshot: CloudConfig = { name: 'alicloud-mse', displayName: 'MSE owned', version: 4, enabled: true,
  mock: true, environmentMock: false, endpoint: 'https://mse.example.test', settings: { instance_id: 'instance-owned' },
  secretKeys: [], operations: [] };
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(accept => { resolve = accept; }); return { promise, resolve };
}
beforeEach(async () => {
  await i18n.changeLanguage('en-US'); rights.clear(); rights.add('alicloud:read'); rights.add('alicloud:write');
  useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 100 });
});
afterEach(async () => {
  cleanup(); vi.restoreAllMocks(); useAuthStore.setState(original);
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});
function mount(onSaved = vi.fn()) { return render(<CloudEditor name="alicloud-mse" onClose={vi.fn()} onSaved={onSaved} />); }

it('requires namespace selection and preserves the explicit empty default in the actual save payload', async () => {
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(snapshot));
  const save = vi.spyOn(cloudApi, 'save').mockResolvedValue(result({ ...snapshot, version: 5, settings: { ...snapshot.settings, namespace_id: '' } }));
  mount(); fireEvent.click(await screen.findByRole('button', { name: 'Save configuration' }));
  await waitFor(() => expect(document.querySelector('.ant-form-item-explain-error')).not.toBeNull()); expect(save).not.toHaveBeenCalled();
  fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Nacos namespace selection' }));
  fireEvent.click(await screen.findByText('Default namespace'));
  const ready = () => screen.getByRole('button', { name: /^(?:loading\s*)?Save configuration$/ });
  await waitFor(() => { expect(ready()).toBeEnabled(); expect(ready()).not.toHaveClass('ant-btn-loading'); });
  fireEvent.click(ready());
  await waitFor(() => expect(save).toHaveBeenCalledOnce());
  expect(save).toHaveBeenCalledWith('alicloud-mse', expect.objectContaining({ expected_version: 4,
    settings: expect.objectContaining({ instance_id: 'instance-owned', namespace_id: '' }) }));
});

it('aborts and discards old tenant configuration loads instead of rendering them for a new tenant', async () => {
  const old = deferred<Awaited<ReturnType<typeof cloudApi.configuration>>>();
  const read = vi.spyOn(cloudApi, 'configuration').mockReturnValueOnce(old.promise)
    .mockResolvedValue(result({ ...snapshot, displayName: 'New tenant config', settings: { instance_id: 'new-instance', namespace_id: '' } }));
  mount(); await waitFor(() => expect(read).toHaveBeenCalledOnce()); const signal = read.mock.calls[0][1];
  await act(async () => { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 101 }); });
  await screen.findByText('New tenant config'); expect(signal?.aborted).toBe(true);
  await act(async () => { old.resolve(result({ ...snapshot, displayName: 'Old tenant private config' })); });
  expect(screen.queryByText('Old tenant private config')).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'MSE instance ID' })).toHaveValue('new-instance');
});

it('does not send a configuration PUT when the session changes while form validation is awaiting', async () => {
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result({ ...snapshot, settings: { ...snapshot.settings, namespace_id: '' } }));
  const save = vi.spyOn(cloudApi, 'save'); mount(); const button = await screen.findByRole('button', { name: 'Save configuration' });
  await act(async () => {
    fireEvent.click(button);
    useAuthStore.setState({ sessionGeneration: 101 });
  });
  await screen.findByRole('button', { name: 'Save configuration' }); expect(save).not.toHaveBeenCalled();
});

it('does not invoke onSaved or publish an old save result after switching tenant during the PUT', async () => {
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result({ ...snapshot, settings: { ...snapshot.settings, namespace_id: '' } }));
  const old = deferred<Awaited<ReturnType<typeof cloudApi.save>>>();
  const save = vi.spyOn(cloudApi, 'save').mockReturnValue(old.promise), onSaved = vi.fn();
  mount(onSaved); fireEvent.click(await screen.findByRole('button', { name: 'Save configuration' }));
  await waitFor(() => expect(save).toHaveBeenCalledOnce());
  await act(async () => { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 101 }); });
  await screen.findByRole('button', { name: 'Save configuration' });
  await act(async () => { old.resolve(result({ ...snapshot, version: 5, displayName: 'Obsolete saved config' })); });
  expect(onSaved).not.toHaveBeenCalled(); expect(screen.queryByText('Obsolete saved config')).not.toBeInTheDocument();
});

it('opens the MSE read-only branch without fetching write-restricted connection configuration', async () => {
  rights.delete('alicloud:write'); const read = vi.spyOn(cloudApi, 'configuration'); mount();
  expect(await screen.findByText('MSE read-only inventory entry')).toBeInTheDocument();
  expect(read).not.toHaveBeenCalled(); expect(screen.queryByRole('button', { name: 'Save configuration' })).not.toBeInTheDocument();
});
