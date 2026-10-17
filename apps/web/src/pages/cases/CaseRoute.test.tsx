import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import CasesPage from '../CasesPage';

describe('case direct links', () => {
  it('opens a case missing from the current list page and respects read-only permissions', async () => {
    await i18n.changeLanguage('zh-CN');
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      const path = url.split('?')[0];
      const body = path === '/api/v1/cases/stable-case-id' ? { case: {
        id: 'stable-case-id', title: 'Off-page investigation', state: 'investigating', severity: 'high',
        asset_ids: [], alert_ids: [], created_at: '2026-09-21T12:00:00Z',
      }, can_write: false } : path.endsWith('/soar-runs') ? [] : { items: [], events: [], total: 0, can_write: false, can_release: false, can_approve: false, durable: true };
      return new Response(JSON.stringify(body));
    }));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const rendered = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/cases/stable-case-id']}>
      <Routes><Route path="/cases/:id" element={<CasesPage />} /></Routes>
    </MemoryRouter></QueryClientProvider>);
    await screen.findByText('Off-page investigation');
    expect(screen.getByRole('button', { name: '流转案件状态' })).toBeDisabled();
    expect(screen.getByRole('button', { name: '执行处置 / YAML 剧本' })).toBeDisabled();
    expect(document.querySelector('.ant-drawer-title')).toHaveTextContent('stable-case-id');
    expect(document.body.textContent).not.toContain('演示模式');
    rendered.unmount(); client.clear(); vi.unstubAllGlobals();
  });
});
