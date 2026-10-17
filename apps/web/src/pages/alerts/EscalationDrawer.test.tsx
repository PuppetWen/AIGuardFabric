import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { __resetDataSource } from '@/api/client';
import type { EscalationConfig, EscalationChange } from '@/api/escalation';
import i18n from '@/locales/i18n';
import { EscalationDrawer } from './EscalationDrawer';

const initial = (): EscalationConfig => ({ version: 2, canWrite: true, automaticAvailable: true, mockMode: false, health: null,
  history: [], channels: [{ channel: 'in-app', enabled: true, minSeverity: 'info' }],
  policies: (['critical', 'high', 'medium', 'low', 'info'] as const).map(severity => ({ since: null, route: {
    severity, enabled: false, responseMinutes: 15, tiers: [{ level: 1, overdueMinutes: 5, target: 'on-call', channels: ['in-app'] }],
  } })),
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
async function mount(config: EscalationConfig, save: (body: EscalationChange) => Response) {
  __resetDataSource(); await i18n.changeLanguage('en-US');
  vi.stubGlobal('fetch', vi.fn(async (input: string, init?: RequestInit) => {
    if (init?.method === 'PUT') return save(JSON.parse(String(init.body)) as EscalationChange);
    return Response.json(input.includes('escalation-history') ? { items: [], total: 0 } : config);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const view = render(<QueryClientProvider client={client}><MemoryRouter><EscalationDrawer onClose={() => {}} /></MemoryRouter></QueryClientProvider>);
  await screen.findByLabelText('Change reason');
  return () => { view.unmount(); client.clear(); };
}
describe('persistent escalation editor', () => {
  it('sends edited values with a version and reloads the confirmed server version', async () => {
    const config = initial(); let sent: EscalationChange | undefined;
    const dispose = await mount(config, body => { sent = body; config.version = 3; config.policies = body.routes.map(route => ({ route, since: null })); return Response.json(config); });
    fireEvent.change(screen.getAllByLabelText('First-response target (minutes)')[0], { target: { value: '20' } });
    fireEvent.click(screen.getByRole('switch', { name: 'critical enable policy' }));
    fireEvent.click(screen.getByLabelText('Include existing alerts (only routes being enabled now)'));
    fireEvent.change(screen.getByLabelText('Change reason'), { target: { value: 'Team response target reviewed' } });
    fireEvent.click(screen.getByRole('button', { name: /Save/ }));
    await waitFor(() => expect(sent?.routes[0]).toMatchObject({ responseMinutes: 20, enabled: true }));
    expect(sent).toMatchObject({ expectedVersion: 2, includeExisting: true, reason: 'Team response target reviewed' });
    await screen.findByText(/Current version v3/);
    dispose();
  });
  it('preserves the draft on conflict and surfaces the reason instead of success', async () => {
    const dispose = await mount(initial(), () => Response.json({ detail: 'Another administrator saved version 3' }, { status: 409 }));
    fireEvent.change(screen.getByLabelText('Change reason'), { target: { value: 'Retain this draft' } });
    fireEvent.click(screen.getByRole('button', { name: /Save/ }));
    await screen.findByText('Not saved; your draft is preserved');
    expect(screen.getByLabelText('Change reason')).toHaveValue('Retain this draft');
    expect(screen.getByText(/Another administrator saved version 3/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Save/ })).toBeEnabled();
    dispose();
  });
  it('disables changes for readers and explains offline automatic execution', async () => {
    const config = { ...initial(), canWrite: false, automaticAvailable: false };
    const save = vi.fn(); const dispose = await mount(config, save);
    expect(screen.getByRole('button', { name: /Save/ })).toBeDisabled();
    expect(screen.getByRole('switch', { name: 'critical enable policy' })).toBeDisabled();
    expect(screen.getByText(/Offline mode: only disabled policies/)).toBeInTheDocument();
    expect(save).not.toHaveBeenCalled(); dispose();
  });
});
