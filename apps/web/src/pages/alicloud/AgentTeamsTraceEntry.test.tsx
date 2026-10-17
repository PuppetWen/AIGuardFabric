import { fireEvent, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { agentTeamsAuditApi } from '@/api/agentTeamsAudit';
import { agentTeamsTraceApi } from '@/api/agentTeamsTrace';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import AgentTeamsAuditPanel from './AgentTeamsAuditPanel';
import { traceEvent, traceMeta, traceUuid, traceWindow } from './trace/traceFixtures';

vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: () => ({ has: (right: string) => ['sources:read', 'alicloud:read'].includes(right), isLoading: false, error: null }) }));
const originalAuth = useAuthStore.getState();
let cache: QueryClient;
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  useAuthStore.setState({ tenant: { id: 'trace-entry-tenant' } as Tenant, sessionGeneration: 5 });
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  vi.spyOn(agentTeamsAuditApi, 'sources').mockResolvedValue({ meta: traceMeta, data: {
    items: [], sources: [], cloudVersion: 4, inventoryAvailable: true, canWrite: false } });
  vi.spyOn(agentTeamsAuditApi, 'events').mockResolvedValue({ meta: traceMeta, data: {
    items: [traceEvent(1), { ...traceEvent(2), traceId: null }], windowFrom: traceWindow.from, windowTo: traceWindow.until } });
  vi.spyOn(agentTeamsTraceApi, 'get');
});
afterEach(async () => { cache.clear(); vi.restoreAllMocks(); useAuthStore.setState(originalAuth); await i18n.changeLanguage('zh-CN'); });
it('audit event entry selects its real trace and record UUID but never starts a Trace GET automatically', async () => {
  render(<QueryClientProvider client={cache}><MemoryRouter><AgentTeamsAuditPanel teams={[]} /></MemoryRouter></QueryClientProvider>);
  await screen.findByText('redacted-event-1');
  const entries = screen.getAllByRole('button', { name: 'Select Trace query' });
  expect(entries).toHaveLength(1);
  expect(screen.getByRole('textbox', { name: 'Trace ID' })).toHaveValue('');
  fireEvent.click(entries[0]);
  expect(screen.getByRole('textbox', { name: 'Trace ID' })).toHaveValue(traceWindow.traceId);
  expect(screen.getByText(/Selected actual audit record/)).toHaveTextContent(traceUuid(1));
  expect(agentTeamsTraceApi.get).not.toHaveBeenCalled();
});
