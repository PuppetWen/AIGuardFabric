import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import CasesPage from '../CasesPage';

afterEach(() => vi.unstubAllGlobals());

describe('finding to case handoff', () => {
  it('requires confirmation and saves the finding and readable asset with the new case', async () => {
    await i18n.changeLanguage('zh-CN');
    let submitted: Record<string, unknown> | undefined;
    vi.stubGlobal('fetch', vi.fn(async (url: string, options?: RequestInit) => {
      const path = url.split('?')[0];
      if (path === '/api/v1/cases' && options?.method === 'POST') {
        submitted = JSON.parse(String(options.body)) as Record<string, unknown>;
        return new Response(JSON.stringify({ case: { id: 'case-1' } }));
      }
      if (path === '/api/v1/findings/finding-1') return new Response(JSON.stringify({ finding: {
        id: 'finding-1', title: 'Agent 工具越权', summary: '已核对的证据', severity: 'high',
        asset_id: 'asset-1', can_read_asset: true,
      } }));
      if (path === '/api/v1/cases/case-1') return new Response(JSON.stringify({ case: {
        id: 'case-1', title: 'Agent 工具越权', state: 'new', severity: 'high',
        alert_ids: [], finding_ids: ['finding-1'], asset_ids: ['asset-1'],
      }, can_write: true }));
      if (path === '/api/v1/assets') return new Response(JSON.stringify({ items: [
        { id: 'asset-1', name: 'Test Agent' },
      ], total: 1, can_write: true }));
      return new Response(JSON.stringify({ items: [], total: 0, can_write: true, events: [] }));
    }));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const view = render(<QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/cases?finding=finding-1']}>
        <Routes><Route path="/cases" element={<CasesPage />} /><Route path="/cases/:id" element={<CasesPage />} /></Routes>
      </MemoryRouter>
    </QueryClientProvider>);
    await screen.findByText('已关联待复核发现；确认后才会创建案件');
    expect(submitted).toBeUndefined();
    fireEvent.click(screen.getByRole('button', { name: /OK|确\s*定/ }));
    await waitFor(() => expect(submitted).toMatchObject({
      title: 'Agent 工具越权', severity: 'high',
      finding_ids: ['finding-1'], asset_ids: ['asset-1'],
    }));
    await screen.findByText('finding-1');
    view.unmount(); client.clear();
  });
});
