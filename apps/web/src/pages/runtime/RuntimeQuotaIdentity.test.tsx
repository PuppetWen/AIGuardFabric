import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ConfigProvider } from 'antd';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import { RuntimeQuotaPanel } from './RuntimeQuotaPanel';

const tenantId = 'a12bc345-6789-4abc-8def-0123456789ab', quotaId = 'b12bc345-6789-4abc-8def-0123456789ab';
const otherQuota = 'c12bc345-6789-4abc-8def-0123456789ab';
const originalAuth = useAuthStore.getState(), originalClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
const caches: QueryClient[] = [];
let copy: ReturnType<typeof vi.fn>, request: ReturnType<typeof vi.fn>;
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  useAuthStore.setState({ tenant: { id: tenantId, slug: 'one' } as Tenant, token: null, sessionGeneration: 1 });
  copy = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', { value: { writeText: copy }, configurable: true });
  request = vi.fn(async (url: string, options?: RequestInit) => {
    expect(options?.method).toBe('GET');
    const path = new URL(String(url), 'http://localhost').pathname;
    if (path === '/api/v1/auth/me') return Response.json({ access: { 'quotas:read': true, 'quotas:write': false }, roles: ['viewer'], superadmin: false });
    if (path !== '/api/v1/quotas') throw new Error(`Unexpected request: ${path}`);
    const other = useAuthStore.getState().tenant?.id !== tenantId;
    return Response.json({ items: [{ quota: { id: other ? otherQuota : quotaId, name: other ? 'Other tenant limit' : 'Current tenant limit',
      scope: 'tenant', dimension: 'requests', window: 'minute', limit: 40, soft_threshold: 0, on_exceed: 'deny', enabled: true, version: 7 },
    used: 3, remaining: 37 }], total: 1, page: 1, page_size: 8, has_more: false });
  });
  vi.stubGlobal('fetch', request);
});
afterEach(async () => {
  cleanup(); caches.splice(0).forEach(cache => cache.clear()); vi.unstubAllGlobals(); vi.restoreAllMocks();
  useAuthStore.setState(originalAuth);
  if (originalClipboard) Object.defineProperty(navigator, 'clipboard', originalClipboard);
  else Reflect.deleteProperty(navigator, 'clipboard');
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});
async function mount() {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } }); caches.push(cache);
  render(<ConfigProvider theme={{ token: { motion: false } }}><QueryClientProvider client={cache}>
    <MemoryRouter><RuntimeQuotaPanel /></MemoryRouter>
  </QueryClientProvider></ConfigProvider>);
  await screen.findByText('Current tenant limit · v7');
}

it('lets a read-only user copy the exact listed UUID and current revision without any write request', async () => {
  await mount();
  expect(screen.getByText(quotaId)).toBeInTheDocument();
  expect(screen.getByText('v7')).toBeInTheDocument();
  expect(copy).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: `Copy quota UUID ${quotaId}` }));
  await screen.findByText('Quota UUID copied');
  expect(copy).toHaveBeenLastCalledWith(quotaId);
  fireEvent.click(screen.getByRole('button', { name: `Copy quota revision ${quotaId}` }));
  await screen.findByText('Current quota revision copied');
  expect(copy).toHaveBeenLastCalledWith('7'); expect(copy).toHaveBeenCalledTimes(2);
  expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
  expect(request.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true);
});

it('reports clipboard rejection truthfully and keeps the actual identity available for manual copy', async () => {
  copy.mockRejectedValue(new Error('Permission denied'));
  await mount(); fireEvent.click(screen.getByRole('button', { name: `Copy quota UUID ${quotaId}` }));
  await screen.findByText('Copy failed. Select the displayed UUID or revision to copy manually.');
  expect(screen.getByText(quotaId)).toBeInTheDocument();
  expect(screen.queryByText('Quota UUID copied')).not.toBeInTheDocument();
  expect(request.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true);
});

it('does not publish a late old-tenant clipboard result into the new tenant table', async () => {
  let resolve!: () => void;
  copy.mockImplementation(() => new Promise<void>(accept => { resolve = accept; }));
  await mount(); fireEvent.click(screen.getByRole('button', { name: `Copy quota UUID ${quotaId}` }));
  await waitFor(() => expect(copy).toHaveBeenCalledTimes(1));
  act(() => useAuthStore.setState({ tenant: { id: 'd12bc345-6789-4abc-8def-0123456789ab', slug: 'two' } as Tenant, sessionGeneration: 2 }));
  await screen.findByText('Other tenant limit · v7');
  await act(async () => { resolve(); });
  expect(screen.queryByText(quotaId)).not.toBeInTheDocument();
  expect(screen.getByText(otherQuota)).toBeInTheDocument();
  expect(screen.queryByText('Quota UUID copied')).not.toBeInTheDocument();
  expect(request.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true);
});
