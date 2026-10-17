import type { ReactNode } from 'react';
import { ConfigProvider } from 'antd';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, vi } from 'vitest';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import { schedulerManagedJobsApi as api } from '@/api/schedulerManagedJobs';
import { schedulerNativeApi as nativeApi } from '@/api/schedulerNative';
import { native, observation, preview, result, state } from './testFixtures';
export const rights = new Set<string>();
const original = useAuthStore.getState(), caches: QueryClient[] = [];
export function installHarness() {
  beforeEach(async () => {
    await i18n.changeLanguage('en-US');
    useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 1 });
    rights.clear(); ['alicloud:read', 'alicloud:write', 'platform:admin'].forEach(value => rights.add(value));
    vi.mocked(useSessionAccess).mockImplementation(() => ({ has: (permission: string) => rights.has(permission), isLoading: false }) as unknown as ReturnType<typeof useSessionAccess>);
    vi.spyOn(api, 'state').mockResolvedValue(result(state()));
    vi.spyOn(nativeApi, 'state').mockResolvedValue(result(native()));
    vi.spyOn(nativeApi, 'receipt').mockResolvedValue(result(observation()));
  });
  afterEach(async () => {
    cleanup(); caches.splice(0).forEach(cache => cache.clear()); vi.restoreAllMocks(); useAuthStore.setState(original);
    await act(async () => { await i18n.changeLanguage('zh-CN'); });
  });
}
export function mount(node: ReactNode) {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } }); caches.push(cache);
  return render(node, { wrapper: ({ children }) => <QueryClientProvider client={cache}>
    <ConfigProvider theme={{ token: { motion: false } }}>{children}</ConfigProvider></QueryClientProvider> });
}
export async function choose(label: string, value: string) {
  fireEvent.mouseDown(screen.getByRole('combobox', { name: label }));
  fireEvent.click(await screen.findByText(value, { selector: '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content' }));
}
export async function adopt() {
  const read = await screen.findByRole('button', { name: 'GET original observation (no redispatch)' });
  await waitFor(() => expect(read).toBeEnabled()); fireEvent.click(read);
  const control = await screen.findByRole('button', { name: 'Adopt current observation and binding version (keep draft)' });
  await waitFor(() => expect(control).toBeEnabled()); fireEvent.click(control);
}
export async function prepare() {
  await adopt(); await choose('Actual task kind', 'report');
  fireEvent.change(screen.getByRole('textbox', { name: 'Mock job name' }), { target: { value: 'Owned report' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'time_expression' }), { target: { value: '0 0/5 * * * ?' } });
  const button = screen.getByRole('button', { name: 'Preview one managed change' });
  await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button);
  await screen.findByRole('region', { name: 'Single-action preview' });
}
export async function confirmApply() {
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm no cloud CAS; a read fingerprint is not an atomic cloud lock' }));
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm callback binding is unenforced and deployment/consumers remain unknown' }));
  const button = screen.getByRole('button', { name: 'Submit one managed change' });
  await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button);
  const confirm = await screen.findByRole('button', { name: 'Confirm single submission' });
  await waitFor(() => { expect(confirm).toBeVisible(); expect(confirm).toBeEnabled(); }); fireEvent.click(confirm);
}
export function mockPrepare() {
  return vi.spyOn(api, 'preview').mockImplementation(async body => result(preview({ id: body.request_id })));
}
export async function readOriginal(id: string) {
  const input = screen.getByRole('textbox', { name: 'Original managed request ID' });
  fireEvent.change(input, { target: { value: id } });
  fireEvent.click(screen.getByRole('button', { name: /GET read original ID$/ }));
}
