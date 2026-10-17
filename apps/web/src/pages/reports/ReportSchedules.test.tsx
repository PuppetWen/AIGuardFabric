import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, expect, it, vi } from 'vitest';
import { __resetDataSource } from '@/api/client';
import i18n from '@/locales/i18n';
import { ReportSchedules } from './ReportSchedules';

afterEach(() => vi.unstubAllGlobals());
const row = { id: 'schedule-one', name: '已有报表', kind: 'findings', format: 'json', cron: '0 4 * * MON',
  enabled: false, version: 3, window_secs: 604800, channel_ids: ['channel-one'] };

it('edits the original schedule with its version and retains selected channels', async () => {
  __resetDataSource(); await i18n.changeLanguage('zh-CN');
  const patches: unknown[] = [];
  const fetcher = vi.fn(async (url: string, options?: RequestInit) => {
    if (options?.method === 'PATCH') { patches.push(JSON.parse(String(options.body))); return Response.json(row); }
    return Response.json(url.includes('/reports/channels')
      ? { items: [{ id: 'channel-one', channel: 'email', enabled: true }] } : { items: [row] });
  });
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const view = render(<QueryClientProvider client={client}><ReportSchedules onGenerated={vi.fn()} /></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('button', { name: /编\s*辑/ }));
  expect(await screen.findByLabelText('计划名称')).toHaveValue('已有报表');
  expect(screen.getByLabelText('统计窗口（天）')).toHaveValue('7');
  fireEvent.change(screen.getByLabelText('计划名称'), { target: { value: '修改后的报表' } });
  fireEvent.click(screen.getByRole('button', { name: '保 存' }));
  await waitFor(() => expect(patches).toHaveLength(1));
  expect(patches[0]).toEqual({ name: '修改后的报表', kind: 'findings', format: 'json', cron: '0 4 * * MON',
    window_secs: 604800, channel_ids: ['channel-one'], expected_version: 3 });
  expect(fetcher.mock.calls.some(([url, options]) => url.endsWith('/schedules/schedule-one') && options?.method === 'PATCH')).toBe(true);
  view.unmount(); client.clear();
});

it('keeps the edited form after a version conflict and does not report success', async () => {
  __resetDataSource(); await i18n.changeLanguage('en-US');
  const generated = vi.fn();
  vi.stubGlobal('fetch', vi.fn(async (url: string, options?: RequestInit) => options?.method === 'PATCH'
    ? Response.json({ title: 'Version conflict', detail: 'Reload this schedule', code: 'conflict' }, { status: 409 })
    : Response.json(url.includes('/reports/channels') ? { items: [] } : { items: [row] })));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const view = render(<QueryClientProvider client={client}><ReportSchedules onGenerated={generated} /></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
  fireEvent.change(await screen.findByLabelText('Schedule name'), { target: { value: 'Unsaved edit' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await screen.findByText(/Reload this schedule/);
  expect(screen.getByLabelText('Schedule name')).toHaveValue('Unsaved edit');
  expect(generated).not.toHaveBeenCalled();
  view.unmount(); client.clear(); await i18n.changeLanguage('zh-CN');
});

it('sends the listed version when deleting and retains the plan after a conflict', async () => {
  __resetDataSource(); await i18n.changeLanguage('en-US');
  const generated = vi.fn();
  const fetcher = vi.fn(async (url: string, options?: RequestInit) => options?.method === 'DELETE'
    ? Response.json({ detail: 'Schedule changed; reload before deleting' }, { status: 409 })
    : Response.json(url.includes('/reports/channels') ? { items: [] } : { items: [row] }));
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const view = render(<QueryClientProvider client={client}><ReportSchedules onGenerated={generated} /></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('button', { name: 'Delete' }));
  fireEvent.click(await screen.findByRole('button', { name: 'OK' }));
  await screen.findByText(/reload before deleting/);
  expect(fetcher.mock.calls.some(([url, options]) => url.endsWith('/schedules/schedule-one?expected_version=3')
    && options?.method === 'DELETE')).toBe(true);
  expect(screen.getByText('已有报表')).toBeInTheDocument();
  expect(generated).not.toHaveBeenCalled();
  view.unmount(); client.clear(); await i18n.changeLanguage('zh-CN');
});
