import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import i18n from '@/locales/i18n';
import { __resetDataSource } from '@/api/client';
import { adaptResponse } from '@/api/adapters';
import fixtures from '@/api/adapters/server-fixtures';
import { downloadText } from '@/utils/download';
import AuditPage from '../AuditPage';
import { AuditExportButton } from './AuditExportButton';

vi.mock('@/utils/download', () => ({ downloadText: vi.fn() }));

describe('audit server listing', () => {
  it('derives sensitivity and displays the committed sequence range', () => {
    const page = adaptResponse('/api/v1/audit', {
      items: [{ ...fixtures.audit, action: 'grant' }],
      total: 1, page: 1, page_size: 15,
    }) as { items: { sensitive: boolean }[] };
    expect(page.items[0].sensitive).toBe(true);
    const check = adaptResponse('/api/v1/audit/verify', {
      passed: true, checked: 3, firstSequence: 1, lastSequence: 3, violations: [],
    }) as { firstSequence: number; lastSequence: number };
    expect([check.firstSequence, check.lastSequence]).toEqual([1, 3]);
  });

  it('sends filters and page changes to the server rather than slicing one response', async () => {
    __resetDataSource();
    await i18n.changeLanguage('zh-CN');
    const requests: URL[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      const request = new URL(url, 'http://localhost');
      requests.push(request);
      return new Response(JSON.stringify({
        items: [fixtures.audit], total: 40,
        page: Number(request.searchParams.get('page') ?? 1), page_size: 15,
      }), { status: 200 });
    }));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
    render(<QueryClientProvider client={client}><MemoryRouter><AuditPage /></MemoryRouter></QueryClientProvider>);
    await screen.findAllByText(fixtures.audit.actor.name);
    fireEvent.click(document.querySelector('.ant-pagination-next button')!);
    await waitFor(() => expect(requests.some((request) => request.searchParams.get('page') === '2')).toBe(true));
    fireEvent.change(screen.getByLabelText(i18n.t('audit.filter.action')), { target: { value: 'campaign-search-7' } });
    await waitFor(() => expect(requests.some((request) =>
      request.searchParams.get('q') === 'campaign-search-7' && request.searchParams.get('page') === '1')).toBe(true));
    client.clear();
  });

  it('downloads the filtered audit data instead of only showing a success toast', async () => {
    await i18n.changeLanguage('zh-CN');
    vi.mocked(downloadText).mockClear();
    const requests: URL[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      requests.push(new URL(url, 'http://localhost'));
      return new Response(JSON.stringify({
        items: [fixtures.audit], total: 1, page: 1, page_size: 200,
      }), { status: 200 });
    }));
    render(<AuditExportButton filters={{ keyword: 'login' }} />);
    fireEvent.click(screen.getByRole('button', { name: i18n.t('audit.exportAll') }));
    await waitFor(() => expect(downloadText).toHaveBeenCalledOnce());
    expect(requests[0].searchParams.get('q')).toBe('login');
    const data = JSON.parse(vi.mocked(downloadText).mock.calls[0][1]) as { total: number; items: unknown[] };
    expect(data.total).toBe(1);
    expect(data.items).toHaveLength(1);
  });
});
