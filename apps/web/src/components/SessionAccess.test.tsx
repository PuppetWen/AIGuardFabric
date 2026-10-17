import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AppLayout, NAV_GROUPS } from './AppLayout';
import { PAGE_PERMISSIONS } from '@/api/sessionAccess';
import { __resetDataSource } from '@/api/client';
import { useAuthStore } from '@/stores/authStore';
import i18n from '@/locales/i18n';

vi.mock('./GlobalSearch', () => ({ GlobalSearch: () => null }));
vi.mock('./NotificationBell', () => ({ NotificationBell: () => null }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
async function mount(path: string, read: () => Response | Promise<Response>) {
  __resetDataSource(); await i18n.changeLanguage('en-US');
  const requested: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    requested.push(url);
    return url.includes('/auth/me') ? read() : Response.json([]);
  }));
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const view = render(<QueryClientProvider client={cache}><MemoryRouter initialEntries={[path]}>
    <Routes><Route element={<AppLayout />}><Route path="*" element={<div data-testid="protected-page">Authorized content</div>} /></Route></Routes>
  </MemoryRouter></QueryClientProvider>);
  return { requested, cache, dispose: () => { view.unmount(); cache.clear(); } };
}
describe('navigation follows server authorization', () => {
  it('covers each sidebar page and hides ungranted links without fetching their pages', async () => {
    for (const item of NAV_GROUPS.flatMap(group => group.items)) expect(PAGE_PERMISSIONS[item.key]).toBeDefined();
    const mounted = await mount('/rules', () => Response.json({ access: { 'assets:read': true, 'findings:read': true }, roles: ['viewer'] }));
    await screen.findByText('Your account cannot open this page');
    expect(screen.queryByTestId('protected-page')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Detection rules' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Asset inventory' })).toBeInTheDocument();
    expect(screen.getByText('rules:read')).toBeInTheDocument();
    expect(mounted.requested.some(url => url.includes('/tenants'))).toBe(false);
    mounted.dispose();
  });
  it('keeps a failed permission lookup closed, then opens after a successful retry', async () => {
    let working = false;
    const mounted = await mount('/rules', () => working
      ? Response.json({ access: { 'rules:read': true }, roles: ['redteam-engineer'] })
      : Response.json({ detail: 'Access lookup unavailable' }, { status: 503 }));
    await screen.findByText(/Access lookup unavailable/);
    expect(screen.queryByTestId('protected-page')).not.toBeInTheDocument();
    working = true;
    await act(async () => { await mounted.cache.invalidateQueries({ queryKey: ['agf', 'session-access'] }); });
    await screen.findByTestId('protected-page');
    expect(screen.getByRole('link', { name: 'Detection rules' })).toBeInTheDocument();
    mounted.dispose();
  });
  it('removes mounted content when access changes and does not reuse it for another session', async () => {
    let readable = true;
    const mounted = await mount('/rules', () => Response.json({ access: { 'rules:read': readable }, roles: readable ? ['redteam-engineer'] : ['viewer'] }));
    await screen.findByTestId('protected-page');
    readable = false;
    act(() => useAuthStore.setState({ sessionGeneration: useAuthStore.getState().sessionGeneration + 1 }));
    await waitFor(() => expect(screen.queryByTestId('protected-page')).not.toBeInTheDocument());
    await screen.findByText('Your account cannot open this page');
    expect(screen.queryByRole('link', { name: 'Detection rules' })).not.toBeInTheDocument();
    mounted.dispose();
  });
});
