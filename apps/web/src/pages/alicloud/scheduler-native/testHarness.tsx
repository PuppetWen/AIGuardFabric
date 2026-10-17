import type { ReactNode } from 'react';
import { ConfigProvider } from 'antd';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, vi } from 'vitest';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import { schedulerNativeApi as api } from '@/api/schedulerNative';
import { observationId, receipt, result, state } from './testFixtures';

export const rights = new Set<string>();
const original = useAuthStore.getState(), caches: QueryClient[] = [];
export function installHarness() {
  beforeEach(async () => {
    await i18n.changeLanguage('en-US');
    useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 1 });
    rights.clear(); ['alicloud:read', 'alicloud:write'].forEach(value => rights.add(value));
    vi.mocked(useSessionAccess).mockImplementation(() => ({ has: (permission: string) => rights.has(permission), isLoading: false }) as unknown as ReturnType<typeof useSessionAccess>);
    vi.spyOn(api, 'state').mockResolvedValue(result(state()));
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
export async function readOriginal() {
  await screen.findByText('actual-configured-application');
  fireEvent.change(screen.getByRole('textbox', { name: 'Original observation ID' }), { target: { value: observationId } });
  fireEvent.click(screen.getByRole('button', { name: /Read original observation receipt$/ }));
  await screen.findByText('Original observation receipt');
}
export async function adopt() {
  fireEvent.click(await screen.findByRole('button', { name: 'Adopt latest local version and the read observation (keep selections)' }));
}
export async function save() {
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Confirm local save' })).not.toBeInTheDocument());
  const consent = screen.getByRole('checkbox', { name: /Confirm full replacement of local associations/ });
  await waitFor(() => expect(consent).toBeEnabled());
  fireEvent.click(consent); fireEvent.click(screen.getByRole('button', { name: 'Save local associations' }));
  const confirm = await screen.findByRole('button', { name: 'Confirm local save' });
  await waitFor(() => { expect(confirm).toBeVisible(); expect(confirm).toBeEnabled(); }); fireEvent.click(confirm);
}
export function mockRead() { return vi.spyOn(api, 'receipt').mockResolvedValue(result(receipt())); }
