import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import fixtures from '@/api/adapters/server-fixtures';
import { __resetDataSource } from '@/api/client';
import i18n from '@/locales/i18n';
import FindingsPage from './FindingsPage';
import { AlertDetail } from './alerts/AlertDetail';
import { DefinitionDetail } from '@/components/DefinitionDetail';

function Location() { const location = useLocation(); return <output aria-label="location">{location.search}</output>; }
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
describe('search result permalinks', () => {
  it.each(['finding', 'alert', 'rule', 'testCase'] as const)('opens %s outside the loaded list and keeps unrelated URL state on close', async kind => {
    __resetDataSource(); await i18n.changeLanguage('en-US');
    const detail = kind === 'finding' ? { ...fixtures.findings, id: 'off-page' }
      : kind === 'alert' ? { alert: { ...fixtures.alerts, id: 'off-page', title: 'Off-page alert' } }
        : kind === 'rule' ? { rule: { name: 'Off-page rule' }, yaml: 'key: off-page\nname: Off-page rule' }
          : { key: 'off-page', title: 'Off-page case', tags: [], turns: [] };
    const fetcher = vi.fn(async (url: string) => new Response(JSON.stringify(
      url.includes('/off-page') ? detail : { items: [], total: 0, page: 1, page_size: 10 }), { status: 200 }));
    vi.stubGlobal('fetch', fetcher);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
    const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/?${kind}=off-page&keep=yes`]}>
      <Location />{kind === 'finding' ? <FindingsPage /> : kind === 'alert' ? <AlertDetail /> : <DefinitionDetail kind={kind} />}
    </MemoryRouter></QueryClientProvider>);
    await waitFor(() => expect(document.querySelector('.ant-drawer-open')).not.toBeNull());
    await waitFor(() => expect(document.querySelector('.ant-drawer-body [aria-busy=true]')).toBeNull());
    expect(document.querySelector('.ant-drawer-body [role=alert]')?.textContent ?? '').not.toContain('Request failed');
    expect(fetcher.mock.calls.some(([url]) => url.includes('/off-page'))).toBe(true);
    if (kind === 'finding') expect(document.querySelector('.ant-drawer-body')?.textContent).toContain(fixtures.findings.summary);
    else if (kind === 'alert') expect(await screen.findByText('Off-page alert')).toBeInTheDocument();
    else expect((screen.getByLabelText('Full definition (read only)') as HTMLTextAreaElement).value).toContain('off-page');
    fireEvent.click(document.querySelector('.ant-drawer-close') as HTMLElement);
    await waitFor(() => expect(screen.getByLabelText('location')).toHaveTextContent('?keep=yes'));
    view.unmount(); client.clear();
  });
  it('keeps a missing detail open with an actionable retry instead of silently showing a list', async () => {
    await i18n.changeLanguage('en-US');
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ detail: 'Alert was removed or is inaccessible' }), { status: 404 })));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
    const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/?alert=missing']}><AlertDetail /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByRole('alert')).toHaveTextContent('Alert was removed or is inaccessible');
    expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument();
    view.unmount(); client.clear();
  });
});
