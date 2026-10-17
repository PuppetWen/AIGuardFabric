import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import fixtures from '@/api/adapters/server-fixtures';
import { __resetDataSource } from '@/api/client';
import i18n from '@/locales/i18n';
import AssetsPage from './AssetsPage';

function Location() { return <output aria-label="location">{useLocation().pathname + useLocation().search}</output>; }
describe('asset detail permalinks', () => {
  it.each(['/assets/cloud-worker-id', '/assets?asset=cloud-worker-id'])('opens the requested asset on a fresh load: %s', async entry => {
    __resetDataSource(); await i18n.changeLanguage('zh-CN');
    const fetcher = vi.fn(async (url: string) => new Response(JSON.stringify(
      url.includes('/assets/cloud-worker-id') ? { asset: { ...fixtures.assets, id: 'cloud-worker-id' }, changes: [] }
        : { items: [], total: 0, page: 1, page_size: 10 }), { status: 200 }));
    vi.stubGlobal('fetch', fetcher);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
    const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}><Location />
      <Routes><Route path="/assets" element={<AssetsPage />} /><Route path="/assets/:assetId" element={<AssetsPage />} /></Routes>
    </MemoryRouter></QueryClientProvider>);
    await waitFor(() => expect(document.querySelector('.ant-drawer-open')?.textContent).toContain(fixtures.assets.name));
    expect(fetcher.mock.calls.some(([url]) => url.includes('/assets/cloud-worker-id'))).toBe(true);
    fireEvent.click(document.querySelector('.ant-drawer-close') as HTMLElement);
    await waitFor(() => expect(screen.getByLabelText('location')).toHaveTextContent(/^\/assets$/));
    view.unmount(); client.clear(); vi.unstubAllGlobals();
  });
  it('explains a removed or unknown asset instead of leaving an empty drawer', async () => {
    __resetDataSource(); await i18n.changeLanguage('en-US');
    vi.stubGlobal('fetch', vi.fn(async (url: string) => new Response(JSON.stringify(
      url.includes('/assets/removed-asset')
        ? { title: 'Not Found', status: 404, detail: 'asset missing' }
        : { items: [], total: 0, page: 1, page_size: 10 }),
    { status: url.includes('/assets/removed-asset') ? 404 : 200 })));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
    const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/assets/removed-asset']}><Location />
      <Routes><Route path="/assets" element={<AssetsPage />} /><Route path="/assets/:assetId" element={<AssetsPage />} /></Routes>
    </MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText('This asset is missing or removed from current inventory')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    await waitFor(() => expect(screen.getByLabelText('location')).toHaveTextContent(/^\/assets$/));
    view.unmount(); client.clear(); vi.unstubAllGlobals();
  });
});
