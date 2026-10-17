import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ConfigProvider, message } from 'antd';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { api, ApiRequestError } from '@/api/client';
import { policiesApi } from '@/api/policies';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import PoliciesPage from '../PoliciesPage';
import { policyDeferred, policyFixture, policyResult } from './policyTestFixtures';

vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
const originalAuth = useAuthStore.getState(), caches: QueryClient[] = [];
let writable = true;
beforeEach(async () => {
  await i18n.changeLanguage('en-US'); writable = true;
  useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 1 });
  vi.mocked(useSessionAccess).mockImplementation(() => ({ has: (permission: string) => permission === 'policies:read'
    || (writable && permission === 'policies:write'), isLoading: false }) as ReturnType<typeof useSessionAccess>);
  vi.spyOn(api, 'policies').mockResolvedValue(policyResult({ items: [policyFixture(3)], total: 1, page: 1, pageSize: 50 }));
  vi.spyOn(policiesApi, 'history').mockResolvedValue(policyResult({ versions: [policyFixture(1)] }));
  vi.spyOn(policiesApi, 'get').mockResolvedValue(policyResult(policyFixture(5)));
});
it('shows unsupported historical actions and prevents publishing their source through restore', async () => {
  vi.mocked(policiesApi.history).mockResolvedValue(policyResult({ versions: [policyFixture(1, { action: 'unknown', rawAction: 'future-action' })] }));
  const restore = vi.spyOn(policiesApi, 'restore'); await mount();
  expect(await screen.findByText(/historical policy has an unknown action/)).toBeInTheDocument();
  const button = screen.getByRole('button', { name: 'Restore as new revision' }); expect(button).toBeDisabled(); fireEvent.click(button);
  expect(restore).not.toHaveBeenCalled(); expect(screen.getByText('Restore uses current revision v3')).toBeInTheDocument();
});
afterEach(async () => {
  cleanup(); caches.forEach(cache => cache.clear()); caches.length = 0;
  act(() => message.destroy()); vi.restoreAllMocks(); useAuthStore.setState(originalAuth);
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});
async function openHistory() {
  await screen.findByText('Owned policy'); fireEvent.click(screen.getByRole('button', { name: '版本 / Versions' }));
  await screen.findByText('Restore uses current revision v3'); await screen.findByRole('button', { name: 'Restore as new revision' });
}
async function mount() {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } }); caches.push(cache);
  render(<QueryClientProvider client={cache}><ConfigProvider theme={{ token: { motion: false } }}>
    <MemoryRouter><PoliciesPage /></MemoryRouter>
  </ConfigProvider></QueryClientProvider>);
  await openHistory();
}
async function confirmRestore(waitForClose = true) {
  await waitFor(() => expect(screen.queryByRole('tooltip')).not.toBeInTheDocument());
  const button = await screen.findByRole('button', { name: 'Restore as new revision' });
  await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button);
  const popup = await screen.findByRole('tooltip');
  await waitFor(() => expect(within(popup).getByText('Restore historical revision 1?')).toBeVisible());
  const confirm = await within(popup).findByRole('button', { name: 'Confirm restored publication' });
  await waitFor(() => { expect(confirm).toBeVisible(); expect(confirm).toBeEnabled(); }); fireEvent.click(confirm);
  // The error alert is set before AntD's promise callback closes this popup.
  if (waitForClose) await waitFor(() => expect(screen.queryByRole('tooltip')).not.toBeInTheDocument());
}

it('retains the sample on restore 409, compares without rebasing, and requires adoption plus a separate restore confirmation', async () => {
  const restore = vi.spyOn(policiesApi, 'restore').mockRejectedValue(new ApiRequestError('Restore conflict', 409, 'conflict', false));
  await mount(); const sample = '{"command":"unsaved sample"}';
  fireEvent.change(screen.getByLabelText('Policy simulation sample'), { target: { value: sample } });
  await confirmRestore(); await screen.findByText('Restore conflict'); expect(restore).toHaveBeenCalledWith(policyFixture().id, 1, 3);
  expect(screen.getByLabelText('Policy simulation sample')).toHaveValue(sample);
  fireEvent.click(screen.getByRole('button', { name: 'Load latest revision to compare' })); await screen.findByText('Server revision v5');
  expect(screen.getByText('Restore uses current revision v3')).toBeInTheDocument(); expect(restore).toHaveBeenCalledTimes(1);
  await confirmRestore(); await screen.findByText('Restore conflict'); expect(restore).toHaveBeenLastCalledWith(policyFixture().id, 1, 3);
  fireEvent.click(screen.getByRole('button', { name: 'Adopt latest policy explicitly' })); await screen.findByText('Replace the draft and save revision?');
  fireEvent.click(screen.getByRole('button', { name: 'Confirm adopting latest policy' })); await screen.findByText('Restore uses current revision v5');
  expect(restore).toHaveBeenCalledTimes(2); expect(screen.getByLabelText('Policy simulation sample')).toHaveValue(sample);
  restore.mockResolvedValue(policyResult(policyFixture(6))); await confirmRestore(); await screen.findByText('Restore uses current revision v6');
  expect(restore).toHaveBeenLastCalledWith(policyFixture().id, 1, 5);
});
it('locks restore while running and ignores its late result after a tenant switch instead of refreshing the new tenant', async () => {
  const pending = policyDeferred<ReturnType<typeof policyResult<ReturnType<typeof policyFixture>>>>();
  const restore = vi.spyOn(policiesApi, 'restore').mockReturnValue(pending.promise);
  await mount(); await confirmRestore(false); await waitFor(() => expect(restore).toHaveBeenCalledOnce());
  expect(screen.getByRole('button', { name: 'Restore as new revision' })).toBeDisabled(); expect(screen.getByLabelText('Policy simulation sample')).toBeDisabled();
  act(() => useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 }));
  await waitFor(() => expect(screen.queryByLabelText('Policy simulation sample')).not.toBeInTheDocument()); await openHistory();
  const count = vi.mocked(api.policies).mock.calls.length;
  await act(async () => { pending.resolve(policyResult(policyFixture(99))); });
  expect(screen.getByText('Restore uses current revision v3')).toBeInTheDocument();
  expect(screen.queryByText('Restore uses current revision v99')).not.toBeInTheDocument(); expect(api.policies).toHaveBeenCalledTimes(count);
});
it('allows reader simulation but no restore and discards a late simulation result after reauthentication', async () => {
  writable = false;
  const pending = policyDeferred<ReturnType<typeof policyResult<unknown>>>();
  const simulate = vi.spyOn(policiesApi, 'simulate').mockReturnValue(pending.promise);
  await mount(); expect(screen.getByRole('button', { name: 'Restore as new revision' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Simulate current policy' })); await waitFor(() => expect(simulate).toHaveBeenCalledOnce());
  act(() => useAuthStore.setState({ sessionGeneration: 2 })); await waitFor(() => expect(screen.queryByLabelText('Policy simulation sample')).not.toBeInTheDocument());
  await openHistory(); await act(async () => { pending.resolve(policyResult({ privateResult: 'old-session decision' })); });
  expect(screen.queryByText(/old-session decision/)).not.toBeInTheDocument();
});
