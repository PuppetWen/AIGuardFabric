import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import i18n from '@/locales/i18n';
import fixtures from '@/api/adapters/server-fixtures';
import { __resetDataSource } from '@/api/client';
import AssetsPage from './AssetsPage';
import FindingsPage from './FindingsPage';
import RulesPage from './RulesPage';
import PoliciesPage from './PoliciesPage';
import CasesPage from './CasesPage';
import AuditPage from './AuditPage';
import ReportsPage from './ReportsPage';
import IngestPage from './IngestPage';

const cases: [string, ReactNode, string][] = [
  ['assets', <AssetsPage />, fixtures.assets.name],
  ['findings', <FindingsPage />, fixtures.findings.title],
  ['rules', <RulesPage />, fixtures.rules.name],
  ['policies', <PoliciesPage />, fixtures.policies.name],
  ['cases', <CasesPage />, fixtures.cases.title],
  ['audit', <AuditPage />, fixtures.audit.actor.name],
  ['reports', <ReportsPage />, fixtures.reports.title],
  ['ingest/sources', <IngestPage />, fixtures['ingest/sources'].receiver],
];

describe('pages render actual server response shapes', () => {
  it('retains the report type and window after moving through all wizard steps', async () => {
    await i18n.changeLanguage('zh-CN');
    const requests: unknown[] = [];
    vi.stubGlobal('fetch', vi.fn(async (_url: string, options?: RequestInit) => {
      if (options?.method === 'POST') {
        requests.push(JSON.parse(String(options.body)));
        return new Response(JSON.stringify({ report: fixtures.reports }), { status: 201 });
      }
      return new Response(JSON.stringify({ items: [fixtures.reports], total: 1, page: 1, page_size: 10 }));
    }));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
    render(<QueryClientProvider client={client}><MemoryRouter><ReportsPage /></MemoryRouter></QueryClientProvider>);
    await screen.findByText(fixtures.reports.title);
    fireEvent.click(screen.getByRole('button', { name: /生成报表/ }));
    for (const label of ['reports.wizard.window', 'reports.wizard.format', 'reports.wizard.schedule']) {
      fireEvent.click(screen.getByRole('button', { name: /下一步/ }));
      await waitFor(() => expect(document.querySelector('.ant-drawer-body label')?.textContent).toContain(i18n.t(label)));
    }
    fireEvent.click(document.querySelector('.ant-drawer-extra button')!);
    await waitFor(() => expect(requests).toEqual([{ kind: 'posture', window_secs: 2592000, format: 'markdown' }]));
    client.clear();
  });

  it.each(cases)('%s renders live rows and details without demo fallback', async (route, element, label) => {
    __resetDataSource();
    await i18n.changeLanguage('zh-CN');
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      const path = url.split('?')[0].replace('/api/v1/', '');
      const fixture = fixtures[path as keyof typeof fixtures];
      const body = path.startsWith('assets/') ? { asset: fixtures.assets, changes: [] }
        : path.startsWith('findings/') ? fixtures.findings
        : { items: fixture ? [fixture] : [], total: fixture ? 1 : 0, page: 1, page_size: 10 };
      return new Response(JSON.stringify(body), { status: 200 });
    }));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
    render(<QueryClientProvider client={client}><MemoryRouter>{element}</MemoryRouter></QueryClientProvider>);
    await waitFor(() => expect(screen.getAllByText(label, { exact: false }).length).toBeGreaterThan(0));
    if (route === 'assets' || route === 'findings') {
      fireEvent.click(screen.getByText(label, { selector: 'a' }));
      await waitFor(() => expect(document.querySelector('.ant-drawer-body')).toBeTruthy());
      await waitFor(() => expect(document.querySelector('.ant-drawer-body')?.textContent).toContain(route === 'assets' ? i18n.t('assets.drawer.invocations') : fixtures.findings.summary));
    }
    expect(document.body.textContent).not.toContain('assets.classification.undefined');
    expect(document.body.textContent).not.toContain('演示模式');
    client.clear();
  });
});
