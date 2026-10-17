import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { __resetDataSource } from '@/api/client';
import { PAGE_PERMISSIONS } from '@/api/sessionAccess';
import { AppProviders } from '@/app/AppProviders';
import { AppRouter } from '@/app/router';
import { NAV_GROUPS } from '@/components/AppLayout';
import i18n from '@/locales/i18n';
import { useAuthStore } from '@/stores/authStore';
import { useUiStore } from '@/stores/uiStore';

vi.mock('@/components/GlobalSearch', () => ({ GlobalSearch: () => null }));
vi.mock('@/components/NotificationBell', () => ({ NotificationBell: () => null }));
vi.mock('echarts-for-react', () => ({ default: () => null }));
vi.mock('@antv/g6', () => ({ Graph: class {
  on() { /* Rendering is covered by TopologyPage's dedicated tests. */ }
  async render() { /* No canvas in jsdom. */ }
  async draw() { /* No canvas in jsdom. */ }
  async fitView() { /* No canvas in jsdom. */ }
  async layout() { /* No canvas in jsdom. */ }
  updateEdgeData() { /* No canvas in jsdom. */ }
  updateNodeData() { /* No canvas in jsdom. */ }
  destroy() { /* No canvas in jsdom. */ }
} }));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  useAuthStore.getState().reset();
});

describe('sidebar routes', () => {
  it('opens every linked page without an access, import, render, or 404 error', async () => {
    __resetDataSource();
    useUiStore.setState({ locale: 'en-US' });
    await i18n.changeLanguage('en-US');
    useAuthStore.setState({ token: 'route-smoke-token', displayName: 'Route tester', role: 'admin' });
    window.history.replaceState({}, '', '/');

    const access = Object.fromEntries(Object.values(PAGE_PERMISSIONS).flat().map((key) => [key, true]));
    vi.stubGlobal('fetch', vi.fn(async (url: string) => url.includes('/auth/me')
      ? Response.json({ access, roles: ['admin'], superadmin: true })
      : Response.json({ detail: 'Offline route fixture' }, { status: 503 })));

    const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
    render(<QueryClientProvider client={cache}><AppProviders><AppRouter /></AppProviders></QueryClientProvider>);

    const paths = NAV_GROUPS.flatMap((group) => group.items);
    for (const item of paths) {
      if (item.key !== '/') {
        const menu = document.querySelector('.agf-menu');
        expect(menu, `${item.key}: menu is missing`).not.toBeNull();
        fireEvent.click(within(menu as HTMLElement).getByRole('link', { name: i18n.t(item.labelKey), hidden: true }));
      }
      await waitFor(() => expect(window.location.pathname).toBe(item.key));
      const titleKey = item.key === '/' ? 'overview.title'
        : item.key === '/security' ? 'nav.security' : `${item.key.slice(1)}.title`;
      const expectedTitle = item.key === '/guide' ? 'Connection and operation guide' : i18n.t(titleKey);
      await waitFor(() => expect(screen.queryByRole('heading', { level: 1, hidden: true }),
        `${item.key}: wrong page component`).toHaveTextContent(expectedTitle), { timeout: 12_000 });
      expect(screen.queryByText(i18n.t('layout.pageError')),
        `${item.key}: page error boundary rendered`).not.toBeInTheDocument();
      expect(screen.queryByText(i18n.t('layout.pageNotFoundHint')),
        `${item.key}: 404 page rendered`).not.toBeInTheDocument();
      expect(screen.queryByText(/Your account cannot open this page/),
        `${item.key}: access denied`).not.toBeInTheDocument();
    }
    cache.clear();
  }, 90_000);

  it('shows account security controls in the selected language', async () => {
    __resetDataSource();
    useUiStore.setState({ locale: 'en-US' });
    await i18n.changeLanguage('en-US');
    useAuthStore.setState({ token: 'route-smoke-token', displayName: 'Route tester', role: 'admin' });
    window.history.replaceState({}, '', '/security');
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({
      enabled: false, required: false, passwordRequired: true,
    })));
    const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
    render(<QueryClientProvider client={cache}><AppProviders><AppRouter /></AppProviders></QueryClientProvider>);

    expect(await screen.findByRole('heading', { level: 1 })).toHaveTextContent('Account security');
    expect(await screen.findByText(/MFA status:/)).toHaveTextContent('Not enrolled');
    expect(screen.getByRole('button', { name: 'Verify password and generate QR code' })).toBeInTheDocument();
    await act(async () => { useUiStore.setState({ locale: 'zh-CN' }); });
    await waitFor(() => expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('账号安全'));
    expect(screen.getByRole('button', { name: '验证密码并生成绑定二维码' })).toBeInTheDocument();
    cache.clear();
  });

  it('opens a linked guide tab and keeps the selected tab in the URL', async () => {
    __resetDataSource();
    useUiStore.setState({ locale: 'en-US' });
    await i18n.changeLanguage('en-US');
    useAuthStore.setState({ token: 'route-smoke-token', displayName: 'Route tester', role: 'admin' });
    window.history.replaceState({}, '', '/guide?tab=mcp');
    vi.stubGlobal('fetch', vi.fn(async (url: string) => url.includes('/auth/me')
      ? Response.json({ access: Object.fromEntries(
        Object.values(PAGE_PERMISSIONS).flat().map((key) => [key, true]),
      ), roles: ['admin'], superadmin: true })
      : Response.json({ detail: 'Offline route fixture' }, { status: 503 })));
    const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
    render(<QueryClientProvider client={cache}><AppProviders><AppRouter /></AppProviders></QueryClientProvider>);
    expect(await screen.findByText('Connect a remote HTTP / SSE MCP server')).toBeVisible();
    expect(screen.getByRole('link', { name: 'MCP management' })).toHaveAttribute('href', '/mcps');
    fireEvent.click(screen.getByRole('tab', { name: 'Getting started' }));
    await waitFor(() => expect(window.location.search).toBe('?tab=start'));
    cache.clear();
  });
});
