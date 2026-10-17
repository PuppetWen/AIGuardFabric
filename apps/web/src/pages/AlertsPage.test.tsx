import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { api } from '@/api/client';
import i18n from '@/locales/i18n';
import AlertsPage from './AlertsPage';

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it('uses a campaign link to search its persisted red-team alerts', async () => {
  await i18n.changeLanguage('en-US');
  const fetchAlerts = vi.spyOn(api, 'alerts').mockResolvedValue({
    data: { items: [], total: 0, page: 1, pageSize: 10, canWrite: false },
    meta: { source: 'live', elapsedMs: 1, at: Date.now() },
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const rendered = render(<QueryClientProvider client={client}>
    <MemoryRouter initialEntries={['/alerts?q=redteam%3Acampaign-1%3A']}><AlertsPage /></MemoryRouter>
  </QueryClientProvider>);
  await waitFor(() => expect(fetchAlerts).toHaveBeenCalledWith(expect.objectContaining({
    keyword: 'redteam:campaign-1:', page: 1,
  })));
  rendered.unmount(); client.clear();
});
