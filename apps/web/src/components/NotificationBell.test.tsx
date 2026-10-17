import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { __resetDataSource } from '@/api/client';
import i18n from '@/locales/i18n';
import { NotificationBell } from './NotificationBell';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
describe('real notification inbox', () => {
  it('opens the delivered body and exact related alert; read status waits for server success', async () => {
    __resetDataSource(); await i18n.changeLanguage('en-US');
    let read = false; let fail = true; const writes: unknown[] = [];
    vi.stubGlobal('fetch', vi.fn(async (_: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        writes.push(JSON.parse(String(init.body)));
        if (fail) return Response.json({ detail: 'Cannot save read state' }, { status: 503 });
        read = true; return Response.json({ marked: 1 });
      }
      return Response.json([{ id: 'delivery-1', subject_kind: 'alert-escalation:2:1', subject_id: 'exact-alert',
        title: 'Escalation notification', body: 'Response deadline exceeded', severity: 'high', at: new Date().toISOString(), read, can_mark: true }]);
    }));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
    const view = render(<QueryClientProvider client={client}><MemoryRouter><NotificationBell /></MemoryRouter></QueryClientProvider>);
    fireEvent.click(screen.getByTestId('notification-bell'));
    fireEvent.click(await screen.findByRole('button', { name: /Escalation notification/ }));
    await screen.findByText('Response deadline exceeded');
    await screen.findAllByText(/Cannot save read state/);
    expect(screen.getByRole('link', { name: 'Open related object' })).toHaveAttribute('href', '/alerts?alert=exact-alert');
    expect(read).toBe(false);
    fail = false;
    await waitFor(() => expect(screen.getByRole('button', { name: 'Mark as read' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Mark as read' }));
    await waitFor(() => expect(read).toBe(true));
    await waitFor(() => expect(screen.queryByRole('button', { name: /Mark as read/ })).toBeNull());
    expect(writes).toEqual([{ ids: ['delivery-1'] }, { ids: ['delivery-1'] }]);
    expect(read).toBe(true); view.unmount(); client.clear();
  });
});
