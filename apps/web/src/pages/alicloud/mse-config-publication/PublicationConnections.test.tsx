import { ConfigProvider } from 'antd';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, expect, it, vi } from 'vitest';
import { cloudApi, type CloudConfig, type CloudSummary } from '@/api/cloud';
import type { ApiResult } from '@/api/dataSource';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import CloudConnections from '../CloudConnections';
import MseConfigPublicationPanel from './MseConfigPublicationPanel';
import { publicationApi } from './api';
import { config, deferred, operationId, result, target } from './testFixtures';
import { installHarness } from './testHarness';

vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();
let cache: QueryClient;
afterEach(() => cache?.clear());
function summary(version = 0): CloudSummary {
  return { name: 'alicloud-mse', displayName: 'MSE', enabled: version > 0, mock: true, configured: version > 0, version };
}
function mount() {
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } });
  return render(<QueryClientProvider client={cache}><ConfigProvider theme={{ token: { motion: false } }}>
    <CloudConnections /><MseConfigPublicationPanel />
  </ConfigProvider></QueryClientProvider>);
}
function connection() { return screen.getByRole('row', { name: /^MSE / }); }
async function saveBinding() {
  fireEvent.click(await screen.findByText('Dedicated Data ID target binding'));
  fireEvent.click(await screen.findByRole('radio', { name: 'Default namespace (explicit empty string)' }));
  fireEvent.click(screen.getByRole('checkbox', { name: /Confirm management of this dedicated JSON Data ID/ }));
  const button = screen.getByRole('button', { name: /Save publication target binding$/ });
  await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button);
}

it('refreshes the visible connection after binding CAS succeeds and preserves the original request draft', async () => {
  let version = 0;
  const list = vi.spyOn(cloudApi, 'list').mockImplementation(async () => result({ items: [summary(version)] }));
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(config(0)));
  const save = vi.spyOn(cloudApi, 'save').mockImplementation(async () => { version = 1; return result(config(1)); });
  const receipt = vi.spyOn(publicationApi, 'receipt'), apply = vi.spyOn(publicationApi, 'apply');
  mount(); await screen.findByRole('row', { name: /^MSE Disabled Mock 0/ });
  fireEvent.change(screen.getByRole('textbox', { name: 'Configuration publication original request UUID' }), { target: { value: operationId } });
  const otherKey = ['agf', 'cloud-connections', 'tenant-other', 9];
  const otherList = result({ items: [summary(7)] }); cache.setQueryData(otherKey, otherList);
  await saveBinding();
  await waitFor(() => expect(within(connection()).getByText('Enabled')).toBeInTheDocument());
  expect(within(connection()).getByText('1')).toBeInTheDocument(); expect(list).toHaveBeenCalledTimes(2);
  expect(save).toHaveBeenCalledWith('alicloud-mse', expect.objectContaining({ expected_version: 0 }));
  expect(cache.getQueryState(otherKey)?.isInvalidated).toBe(false);
  expect(cache.getQueryData(otherKey)).toEqual(otherList);
  expect(screen.getByRole('textbox', { name: 'Configuration publication original request UUID' })).toHaveValue(operationId);
  expect(receipt).not.toHaveBeenCalled(); expect(apply).not.toHaveBeenCalled();
});

it.each(['HTTP 401', 'HTTP 409'])('does not refresh the connection or discard a binding draft after %s', async message => {
  const list = vi.spyOn(cloudApi, 'list').mockResolvedValue(result({ items: [summary()] }));
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(config(0)));
  vi.spyOn(cloudApi, 'save').mockRejectedValue(new Error(message));
  mount(); await screen.findByRole('row', { name: /^MSE Disabled Mock 0/ });
  await saveBinding(); await screen.findByText(message);
  expect(list).toHaveBeenCalledTimes(1); expect(within(connection()).getByText('Disabled')).toBeInTheDocument();
  expect(screen.getByText('Save uses configuration version 0')).toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Dedicated Data ID' })).toHaveValue(target.dataId);
});

it('does not invalidate the new tenant list when an old tenant binding save arrives late', async () => {
  const pending = deferred<ApiResult<CloudConfig>>();
  const list = vi.spyOn(cloudApi, 'list').mockResolvedValue(result({ items: [summary()] }));
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(config(0)));
  const save = vi.spyOn(cloudApi, 'save').mockReturnValue(pending.promise);
  mount(); await screen.findByRole('row', { name: /^MSE Disabled Mock 0/ }); await saveBinding();
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  act(() => useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 }));
  await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
  await act(async () => { pending.resolve(result(config(1))); });
  expect(list).toHaveBeenCalledTimes(2); expect(within(connection()).getByText('Disabled')).toBeInTheDocument();
  expect(screen.queryByText('Save uses configuration version 1')).not.toBeInTheDocument();
});
