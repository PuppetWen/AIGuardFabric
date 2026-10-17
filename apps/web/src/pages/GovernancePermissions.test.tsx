import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import RulesPage from './RulesPage';
import FindingsPage from './FindingsPage';
import { __resetDataSource } from '@/api/client';
import i18n from '@/locales/i18n';

vi.mock('./rules/CorrelationConsole', () => ({ CorrelationConsole: () => null }));
vi.mock('@/components/DefinitionDetail', () => ({ DefinitionDetail: () => null }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
it('reader lists expose inspectable resources without writable menus', async () => {
  __resetDataSource(); await i18n.changeLanguage('en-US');
  const fetcher = vi.fn(async (url: string) => Response.json({
    items: url.includes('/rules') ? [{ key: 'READABLE', name: 'Inspectable rule', domain: 'prompt-attack',
      severity: 'high', enabled: true, rollout_percent: 100, version: 2, read_only: true, lifecycle: 'ga' }]
      : [{ id: 'finding-1', title: 'Inspectable finding', domain: 'prompt-attack', severity: 'high', state: 'pending' }],
    total: 1, page: 1, page_size: 10, can_write: false,
  }));
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const view = render(<QueryClientProvider client={client}><MemoryRouter><RulesPage /><FindingsPage /></MemoryRouter></QueryClientProvider>);
  await screen.findByText('Inspectable rule'); await screen.findByText('Inspectable finding');
  expect(screen.getByRole('button', { name: 'New rule' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'View / revisions' })).toBeEnabled();
  expect(screen.getByRole('switch')).toBeDisabled();
  expect(screen.getByRole('slider')).toHaveAttribute('aria-disabled', 'true');
  await waitFor(() => expect(screen.getByRole('combobox', { name: /Inspectable finding/ })).toBeDisabled());
  expect(fetcher.mock.calls.every(call => !call[0].includes('/test'))).toBe(true);
  view.unmount(); client.clear();
});
