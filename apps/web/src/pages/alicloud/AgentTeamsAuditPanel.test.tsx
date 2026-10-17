import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { agentTeamsAuditApi } from '@/api/agentTeamsAudit';
import { useAuthStore } from '@/stores/authStore';
import type { AgentTeamsAuditBinding, AgentTeamsAuditBindResult, AgentTeamsAuditEvents, AgentTeamsAuditSources } from '@/types/agentTeamsAudit';
import type { AgentTeam, Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import AgentTeamsAuditPanel from './AgentTeamsAuditPanel';

const rights = new Set<string>();
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: () => ({ has: (permission: string) => rights.has(permission), isLoading: false, error: null }) }));
const meta = { source: 'live' as const, elapsedMs: 1, at: Date.now() };
const binding: AgentTeamsAuditBinding = {
  sourceId: 'source-one', sourceName: 'Application audit', version: 3, bindingId: 'binding-one',
  cloudVersion: 4, scopeId: 'scope-one', mocked: false, state: 'active', acceptsEvents: true, boundAt: '2026-09-20T10:00:00Z',
  lastEventAt: '2026-09-20T10:01:00Z', coverageStart: '2026-09-20T10:00:00Z', completeWindow: false,
};
const sourceData: AgentTeamsAuditSources = { items: [binding],
  sources: [{ id: binding.sourceId, name: binding.sourceName, enabled: true }], cloudVersion: 4,
  inventoryAvailable: true, canWrite: true };
const firstPage: AgentTeamsAuditEvents = { items: [{ id: 'record-one', eventId: 'event-one',
  eventTime: '2026-09-20T10:01:00Z', receivedAt: '2026-09-20T10:01:01Z', kind: 'message',
  sourceId: binding.sourceId, sourceName: binding.sourceName, fromTeam: 'team-one', fromWorker: 'worker-one',
  traceId: '11111111111111111111111111111111', spanId: '2222222222222222',
  messagePreview: 'token=[REDACTED]', durationMs: null, mocked: false, authorizationStatus: 'unknown', authorized: null }],
  nextCursor: 'cursor-one', windowFrom: '2026-09-19T10:01:00Z', windowTo: '2026-09-20T10:01:00Z' };
const originalAuth = useAuthStore.getState();
const caches: QueryClient[] = [];
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  rights.clear();
  ['sources:read', 'alicloud:read', 'sources:write', 'alicloud:write'].forEach(right => rights.add(right));
  useAuthStore.setState({ tenant: { id: 'tenant-one' } as Tenant, sessionGeneration: 1 });
  vi.spyOn(agentTeamsAuditApi, 'sources').mockResolvedValue({ data: sourceData, meta });
  vi.spyOn(agentTeamsAuditApi, 'events').mockResolvedValue({ data: firstPage, meta });
});
afterEach(async () => {
  caches.forEach(cache => cache.clear()); caches.length = 0;
  vi.restoreAllMocks(); useAuthStore.setState(originalAuth);
  await i18n.changeLanguage('zh-CN');
});
function mount(teams: AgentTeam[] = []) {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  caches.push(cache);
  return render(<QueryClientProvider client={cache}><MemoryRouter><AgentTeamsAuditPanel teams={teams} /></MemoryRouter></QueryClientProvider>);
}

describe('AgentTeams audit onboarding and evidence', () => {
  it('shows observed evidence, independent coverage and a credential-free authenticated example', async () => {
    const view = mount();
    await screen.findByText('token=[REDACTED]');
    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(screen.getByText('Coverage completeness unknown')).toBeInTheDocument();
    expect(screen.getByText('Unknown')).toBeInTheDocument();
    expect(screen.queryByText('null ms')).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Create an API key with only sources:write' }))
      .toHaveAttribute('href', '/settings?tab=apiKeys&createKey=1&scopes=sources%3Awrite');
    expect(screen.getByRole('link', { name: /Open Log ingest/ })).toHaveAttribute('href', '/ingest');
    const payload = view.container.querySelector('pre')?.textContent;
    expect(JSON.parse(payload ?? '{}')).toMatchObject({ binding_id: binding.bindingId, events: [{ kind: 'heartbeat' }] });
    expect(payload).not.toMatch(/authorized|tenant|account|asset_id/i);
    expect(view.container.textContent).toContain('Read-Host');
    expect(view.container.textContent).toContain('tenant-scoped, not restricted to this source');
  });

  it('does not fetch without both read permissions and hides management for readers', async () => {
    rights.delete('sources:read');
    const closed = mount();
    expect(await screen.findByText('Viewing audit requires sources:read and alicloud:read.')).toBeInTheDocument();
    expect(agentTeamsAuditApi.sources).not.toHaveBeenCalled();
    expect(agentTeamsAuditApi.events).not.toHaveBeenCalled();
    closed.unmount();
    rights.add('sources:read'); rights.delete('alicloud:write');
    mount();
    await screen.findByText('token=[REDACTED]');
    expect(screen.queryByRole('button', { name: 'Rebind' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Disable' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Bind selected source' })).not.toBeInTheDocument();
  });

  it('uses only a heartbeat for connection checks even when inventory exists', async () => {
    const team: AgentTeam = { id: 'team-one', name: 'team-one', workspaceId: 'instance-one', region: 'cn-hangzhou',
      memberCount: 1, members: [{ id: 'worker-one', name: 'worker-one', role: 'worker', model: '', status: 'active', invocations24h: 0 }],
      dag: [], crossTeamCalls24h: 0, riskScore: 0, createdAt: binding.boundAt };
    const view = mount([team, { ...team, id: 'team-two', name: 'team-two', members: [{ ...team.members[0], id: 'worker-two', name: 'worker-two' }] }]);
    await screen.findByRole('button', { name: 'Update example time and event ID' });
    const payload = JSON.parse(view.container.querySelector('pre')?.textContent ?? '{}');
    expect(payload).toMatchObject({ binding_id: binding.bindingId, events: [{ kind: 'heartbeat' }] });
    expect(Object.keys(payload.events[0]).sort()).toEqual(['event_id', 'event_time', 'kind']);
  });

  it('generates a distinct heartbeat event ID when choosing another source binding', async () => {
    vi.mocked(agentTeamsAuditApi.sources).mockResolvedValue({ data: { ...sourceData,
      items: [binding, { ...binding, sourceId: 'source-two', sourceName: 'Second source', bindingId: 'binding-two' }],
      sources: [...sourceData.sources, { id: 'source-two', name: 'Second source', enabled: true }] }, meta });
    const view = mount();
    await screen.findByRole('button', { name: 'Update example time and event ID' });
    const first = JSON.parse(view.container.querySelector('pre')?.textContent ?? '{}');
    fireEvent.click(screen.getAllByRole('button', { name: 'Example' })[1]);
    await waitFor(() => expect(JSON.parse(view.container.querySelector('pre')?.textContent ?? '{}').binding_id).toBe('binding-two'));
    const second = JSON.parse(view.container.querySelector('pre')?.textContent ?? '{}');
    expect(second.events[0].event_id).not.toBe(first.events[0].event_id);
    expect(second.events[0].kind).toBe('heartbeat');
  });

  it('also honors the backend write capability and distinguishes stale from active', async () => {
    vi.mocked(agentTeamsAuditApi.sources).mockResolvedValue({ data: { ...sourceData, canWrite: false,
      items: [{ ...binding, state: 'stale', completeWindow: true }] }, meta });
    mount();
    await screen.findByText('Stale');
    expect(screen.getByText('Complete window')).toBeInTheDocument();
    expect(screen.queryByText('Active')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Rebind' })).not.toBeInTheDocument();
  });

  it('keeps valid stale examples available and hides a stale invalid binding', async () => {
    const read = vi.mocked(agentTeamsAuditApi.sources);
    read.mockResolvedValue({ data: { ...sourceData, items: [{ ...binding, state: 'stale', acceptsEvents: true }] }, meta });
    const view = mount();
    await screen.findByRole('button', { name: 'Update example time and event ID' });
    expect(view.container.querySelector('pre')).not.toBeNull();
    read.mockResolvedValue({ data: { ...sourceData, items: [{ ...binding, state: 'stale', acceptsEvents: false }] }, meta });
    fireEvent.click(screen.getByRole('button', { name: 'Refresh audit' }));
    await screen.findByText('This binding is no longer valid. Complete inventory, rebind and update the sender binding ID.');
    expect(screen.getByText('Invalid binding')).toBeInTheDocument();
    expect(view.container.querySelector('pre')).toBeNull();
  });

  it('paginates with the server cursor and clears it when refreshed', async () => {
    const read = vi.mocked(agentTeamsAuditApi.events);
    read.mockImplementation(async cursor => ({ data: cursor ? { ...firstPage, nextCursor: undefined,
      items: [{ ...firstPage.items[0], id: 'record-two', eventId: 'event-two', messagePreview: 'second-page-message' }] } : firstPage, meta }));
    mount();
    await screen.findByText('token=[REDACTED]');
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
    await screen.findByText('second-page-message');
    expect(read).toHaveBeenLastCalledWith('cursor-one');
    expect(screen.queryByText('token=[REDACTED]')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh audit' }));
    await screen.findByText('token=[REDACTED]');
    expect(read).toHaveBeenLastCalledWith(undefined);
    expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled();
  });

  it('uses the displayed version for disabling and refreshes the binding', async () => {
    const update = vi.spyOn(agentTeamsAuditApi, 'bind').mockResolvedValue({ data: { ...binding, version: 4, enabled: false }, meta });
    const read = vi.mocked(agentTeamsAuditApi.sources);
    read.mockResolvedValueOnce({ data: sourceData, meta }).mockResolvedValue({ data: { ...sourceData,
      items: [{ ...binding, version: 4, state: 'disabled' }] }, meta });
    const view = mount();
    await screen.findByRole('button', { name: 'Disable' });
    fireEvent.click(screen.getByRole('button', { name: 'Disable' }));
    await screen.findByText('Audit source disabled.');
    expect(update).toHaveBeenCalledWith(binding.sourceId, 3, false);
    await screen.findByText('Disabled');
    expect(view.container.querySelector('pre')).toBeNull();
  });

  it('keeps historical evidence visible after all audit sources are disabled', async () => {
    vi.mocked(agentTeamsAuditApi.sources).mockResolvedValue({ data: { ...sourceData,
      items: [{ ...binding, state: 'disabled', acceptsEvents: false }] }, meta });
    const view = mount();
    await screen.findByText('token=[REDACTED]');
    expect(screen.getByText(/Audit sources are disabled and new ingest has stopped/)).toBeInTheDocument();
    expect(screen.queryByText('No enabled audit source is connected. Call volume and authorization are unobserved.')).not.toBeInTheDocument();
    expect(view.container.querySelector('pre')).toBeNull();
  });

  it('offers setup guidance for an empty unsynchronized instance without fabricated evidence', async () => {
    vi.mocked(agentTeamsAuditApi.sources).mockResolvedValue({ data: { items: [], sources: [], cloudVersion: 0,
      inventoryAvailable: false, canWrite: true }, meta });
    vi.mocked(agentTeamsAuditApi.events).mockResolvedValue({ data: { ...firstPage, items: [], nextCursor: null }, meta });
    const view = mount();
    await screen.findByText('No enabled audit source is connected. Call volume and authorization are unobserved.');
    expect(screen.getByText('Complete inventory for the current instance before binding audit sources.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Bind selected source' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
    expect(view.container.querySelector('pre')).toBeNull();
    expect(screen.queryByText('token=[REDACTED]')).not.toBeInTheDocument();
  });

  it('discards old messages and cursors when the tenant changes', async () => {
    const read = vi.mocked(agentTeamsAuditApi.events);
    read.mockImplementation(async cursor => ({ data: useAuthStore.getState().tenant?.id === 'tenant-two'
      ? { ...firstPage, items: [], nextCursor: undefined }
      : cursor ? { ...firstPage, items: [{ ...firstPage.items[0], messagePreview: 'old-tenant-page' }] } : firstPage, meta }));
    mount();
    await screen.findByText('token=[REDACTED]');
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
    await screen.findByText('old-tenant-page');
    act(() => useAuthStore.setState({ tenant: { id: 'tenant-two' } as Tenant }));
    await screen.findByText('No events have been collected in this window. Send logs, then refresh.');
    await waitFor(() => expect(read).toHaveBeenLastCalledWith(undefined));
    expect(screen.queryByText('old-tenant-page')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled();
  });

  it('does not refetch an old tenant after its pending binding write completes', async () => {
    let settle!: (value: { data: AgentTeamsAuditBindResult; meta: typeof meta }) => void;
    vi.spyOn(agentTeamsAuditApi, 'bind').mockImplementation(() => new Promise(resolve => { settle = resolve; }));
    mount();
    await screen.findByRole('button', { name: 'Disable' });
    fireEvent.click(screen.getByRole('button', { name: 'Disable' }));
    await waitFor(() => expect(agentTeamsAuditApi.bind).toHaveBeenCalledOnce());
    act(() => useAuthStore.setState({ tenant: { id: 'tenant-two' } as Tenant }));
    await waitFor(() => expect(agentTeamsAuditApi.sources).toHaveBeenCalledTimes(2));
    await act(async () => { settle({ data: { ...binding, version: 4, enabled: false }, meta }); });
    expect(agentTeamsAuditApi.sources).toHaveBeenCalledTimes(2);
    expect(screen.queryByText('Audit source disabled.')).not.toBeInTheDocument();
  });

  it('surfaces a transport failure without a fabricated fallback', async () => {
    vi.mocked(agentTeamsAuditApi.events).mockRejectedValue(new Error('audit backend unavailable'));
    const view = mount();
    await screen.findByText('audit backend unavailable');
    expect(screen.queryByText('token=[REDACTED]')).not.toBeInTheDocument();
    expect(view.container.textContent).not.toContain('No events have been collected');
    expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
  });
});
