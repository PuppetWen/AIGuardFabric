import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiRequestError, type ApiResult } from '@/api/client';
import { agentTeamsTraceApi } from '@/api/agentTeamsTrace';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import type { AgentTeamsTrace, TraceSelection } from '@/types/agentTeamsTrace';
import i18n from '@/locales/i18n';
import AgentTeamsTracePanel from './AgentTeamsTracePanel';
import { deferred, traceEvent, traceFixture, traceMeta, traceUuid, traceWindow, unavailableTrace } from './trace/traceFixtures';

const rights = new Set<string>();
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: () => ({ has: (right: string) => rights.has(right), isLoading: false, error: null }) }));
const originalAuth = useAuthStore.getState();
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  rights.clear(); ['sources:read', 'alicloud:read'].forEach(right => rights.add(right));
  useAuthStore.setState({ tenant: { id: 'trace-tenant-one', slug: 'trace-one' } as Tenant, sessionGeneration: 10 });
  vi.spyOn(agentTeamsTraceApi, 'get').mockResolvedValue({ data: traceFixture(), meta: traceMeta });
});
afterEach(async () => { vi.restoreAllMocks(); useAuthStore.setState(originalAuth); await i18n.changeLanguage('zh-CN'); });
function mount(selection?: TraceSelection) {
  return render(<MemoryRouter><AgentTeamsTracePanel selection={selection} /></MemoryRouter>);
}
function fill(traceId = traceWindow.traceId) {
  fireEvent.change(screen.getByRole('textbox', { name: 'Trace ID' }), { target: { value: traceId } });
  fireEvent.change(screen.getByLabelText('Trace from UTC'), { target: { value: '2026-09-19T10:00:00' } });
  fireEvent.change(screen.getByLabelText('Trace until UTC'), { target: { value: '2026-09-20T10:00:00' } });
}
async function query() {
  fill(); fireEvent.click(screen.getByRole('button', { name: 'Query Trace' }));
  await screen.findByText('redacted-event-1');
}

describe('Controlled Trace observation query', () => {
  it('never GETs on mount or event selection; an actual event ID only prefills the manual form', () => {
    const view = mount();
    expect(agentTeamsTraceApi.get).not.toHaveBeenCalled();
    expect(screen.getByText(/No query yet/)).toBeInTheDocument();
    view.rerender(<MemoryRouter><AgentTeamsTracePanel selection={{ traceId: traceWindow.traceId, recordId: traceUuid(1), revision: 1 }} /></MemoryRouter>);
    expect(screen.getByRole('textbox', { name: 'Trace ID' })).toHaveValue(traceWindow.traceId);
    expect(screen.getByText(/Selected actual audit record/)).toHaveTextContent(traceUuid(1));
    expect(agentTeamsTraceApi.get).not.toHaveBeenCalled();
  });
  it.each(['sources:read', 'alicloud:read'])('hides evidence and avoids GET when %s is missing', right => {
    rights.delete(right); mount();
    expect(screen.getByText(/Viewing Trace requires alicloud:read and sources:read/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Query Trace' })).not.toBeInTheDocument();
    expect(agentTeamsTraceApi.get).not.toHaveBeenCalled();
  });
  it('submits exact UTC bounds and replaces event pages without concatenation, leaving full graph evidence intact', async () => {
    const next = { ...traceFixture(), items: [traceEvent(2)], nextCursor: null };
    vi.mocked(agentTeamsTraceApi.get).mockResolvedValueOnce({ data: traceFixture(), meta: traceMeta })
      .mockResolvedValueOnce({ data: next, meta: traceMeta });
    mount(); await query();
    expect(agentTeamsTraceApi.get).toHaveBeenNthCalledWith(1, traceWindow, undefined, expect.any(AbortSignal));
    fireEvent.click(screen.getByRole('button', { name: 'Next Trace event page' }));
    await screen.findByText('redacted-event-2');
    expect(screen.queryByText('redacted-event-1')).not.toBeInTheDocument();
    expect(screen.getByText('Event page 2')).toBeInTheDocument();
    expect(screen.getByText(/returned 2 nodes/)).toBeInTheDocument();
    expect(agentTeamsTraceApi.get).toHaveBeenNthCalledWith(2, traceWindow, 'opaque-first-cursor', expect.any(AbortSignal));
  });
  it('preserves the saved page on409, blocks navigation and only explicit refresh establishes a new cursor', async () => {
    vi.mocked(agentTeamsTraceApi.get).mockResolvedValueOnce({ data: traceFixture(), meta: traceMeta })
      .mockRejectedValueOnce(new ApiRequestError('Snapshot changed', 409, 'conflict', false))
      .mockResolvedValueOnce({ data: { ...traceFixture(), items: [traceEvent(2)] }, meta: traceMeta });
    mount(); await query();
    fireEvent.click(screen.getByRole('button', { name: 'Next Trace event page' }));
    await screen.findByText(/Records or cloud scope changed \(409\)/);
    expect(screen.getByText('redacted-event-1')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next Trace event page' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Previous Trace event page' })).toBeDisabled();
    expect(agentTeamsTraceApi.get).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByRole('button', { name: 'Refresh Trace query' }));
    await screen.findByText('redacted-event-2');
    expect(screen.queryByText('redacted-event-1')).not.toBeInTheDocument();
    expect(agentTeamsTraceApi.get).toHaveBeenNthCalledWith(3, traceWindow, undefined, expect.any(AbortSignal));
    expect(screen.getByText('Event page 1')).toBeInTheDocument();
  });
  it('restores cached firstpage without GET or a new watermark and keeps the old cursor until explicit refresh', async () => {
    const first = traceFixture();
    const second = { ...traceFixture(), items: [traceEvent(2)], nextCursor: null };
    const fresh = { ...traceFixture(3), items: [traceEvent(3)], asOfReceivedAt: '2026-09-20T10:00:02.000Z' };
    vi.mocked(agentTeamsTraceApi.get).mockResolvedValueOnce({ data: first, meta: traceMeta })
      .mockResolvedValueOnce({ data: second, meta: traceMeta })
      .mockRejectedValueOnce(new ApiRequestError('Late committed record changed the snapshot', 409, 'conflict', false))
      .mockResolvedValueOnce({ data: fresh, meta: traceMeta });
    mount(); await query();
    fireEvent.click(screen.getByRole('button', { name: 'Next Trace event page' }));
    await screen.findByText('redacted-event-2');
    fireEvent.click(screen.getByRole('button', { name: 'Previous Trace event page' }));
    await screen.findByText('redacted-event-1');
    expect(screen.queryByText('redacted-event-2')).not.toBeInTheDocument();
    expect(screen.getByText(first.asOfReceivedAt)).toBeInTheDocument();
    expect(screen.getByText('Event page 1')).toBeInTheDocument();
    expect(agentTeamsTraceApi.get).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByRole('button', { name: 'Next Trace event page' }));
    await screen.findByText(/Records or cloud scope changed \(409\)/);
    expect(agentTeamsTraceApi.get).toHaveBeenNthCalledWith(3, traceWindow, 'opaque-first-cursor', expect.any(AbortSignal));
    expect(screen.getByText('redacted-event-1')).toBeInTheDocument();
    expect(screen.getByText(first.asOfReceivedAt)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next Trace event page' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh Trace query' }));
    await screen.findByText('redacted-event-3');
    expect(screen.getByText(fresh.asOfReceivedAt)).toBeInTheDocument();
    expect(screen.queryByText(first.asOfReceivedAt)).not.toBeInTheDocument();
    expect(agentTeamsTraceApi.get).toHaveBeenNthCalledWith(4, traceWindow, undefined, expect.any(AbortSignal));
  });
  it('distinguishes inventory unavailable (unknown total) from a valid window with zero observed events', async () => {
    vi.mocked(agentTeamsTraceApi.get).mockResolvedValueOnce({ data: unavailableTrace(), meta: traceMeta })
      .mockResolvedValueOnce({ data: traceFixture(0), meta: traceMeta });
    mount(); fill(); fireEvent.click(screen.getByRole('button', { name: 'Query Trace' }));
    await screen.findByText('Unknown (inventory unavailable)');
    expect(screen.getByText(/unknown event count is not zero/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh Trace query' }));
    await screen.findByText(/The scope is valid but this Trace was not observed/);
    expect(screen.queryByText('Unknown (inventory unavailable)')).not.toBeInTheDocument();
    expect(screen.getByText(/Graph state unobserved/)).toBeInTheDocument();
  });
  it('rejects an over30day draft before GET and explains UTC and node limits', () => {
    mount(); fill();
    fireEvent.change(screen.getByLabelText('Trace from UTC'), { target: { value: '2026-08-01T10:00:00' } });
    fireEvent.click(screen.getByRole('button', { name: 'Query Trace' }));
    expect(screen.getByText(/Use a positive window of at most 30 days/)).toBeInTheDocument();
    expect(agentTeamsTraceApi.get).not.toHaveBeenCalled();
    expect(screen.getByText(/Inputs are UTC/)).toHaveTextContent('2000 observed nodes');
  });
  it('invalidates an old query promise and aborts it when the query draft changes', async () => {
    const delayed = deferred<ApiResult<AgentTeamsTrace>>();
    vi.mocked(agentTeamsTraceApi.get).mockReturnValueOnce(delayed.promise);
    mount(); fill(); fireEvent.click(screen.getByRole('button', { name: 'Query Trace' }));
    const signal = vi.mocked(agentTeamsTraceApi.get).mock.calls[0][2];
    fireEvent.change(screen.getByRole('textbox', { name: 'Trace ID' }), { target: { value: 'sdk:new-query' } });
    expect(signal?.aborted).toBe(true);
    await act(async () => delayed.resolve({ data: traceFixture(), meta: traceMeta }));
    expect(screen.queryByText('redacted-event-1')).not.toBeInTheDocument();
    expect(screen.getByText(/No query yet/)).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: 'Trace ID' })).toHaveValue('sdk:new-query');
  });
  it('clears the saved cursor when a time bound changes and sends only a fresh manual query', async () => {
    mount(); await query();
    fireEvent.change(screen.getByLabelText('Trace until UTC'), { target: { value: '2026-09-20T09:00:00' } });
    expect(screen.queryByText('redacted-event-1')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Next Trace event page' })).not.toBeInTheDocument();
    expect(agentTeamsTraceApi.get).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Query Trace' }));
    await screen.findByText('redacted-event-1');
    expect(agentTeamsTraceApi.get).toHaveBeenNthCalledWith(2, { ...traceWindow, until: '2026-09-20T09:00:00.000Z' }, undefined, expect.any(AbortSignal));
    expect(screen.getByText('Event page 1')).toBeInTheDocument();
  });
  it.each(['tenant', 'session'])('discards a late response after %s changes and clears saved scope evidence', async change => {
    const delayed = deferred<ApiResult<AgentTeamsTrace>>();
    vi.mocked(agentTeamsTraceApi.get).mockReturnValueOnce(delayed.promise);
    mount(); fill(); fireEvent.click(screen.getByRole('button', { name: 'Query Trace' }));
    const signal = vi.mocked(agentTeamsTraceApi.get).mock.calls[0][2];
    act(() => useAuthStore.setState(change === 'tenant'
      ? { tenant: { id: 'trace-tenant-two', slug: 'trace-two' } as Tenant }
      : { sessionGeneration: 11 }));
    await act(async () => delayed.resolve({ data: traceFixture(), meta: traceMeta }));
    expect(signal?.aborted).toBe(true);
    expect(screen.queryByText('redacted-event-1')).not.toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: 'Trace ID' })).toHaveValue('');
    expect(agentTeamsTraceApi.get).toHaveBeenCalledTimes(1);
  });
  it('removes previously visible evidence when either read permission is lost', async () => {
    const view = mount(); await query(); rights.delete('sources:read');
    view.rerender(<MemoryRouter><AgentTeamsTracePanel /></MemoryRouter>);
    expect(screen.queryByText('redacted-event-1')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Query Trace' })).not.toBeInTheDocument();
  });
  it('explains explicit SDK collection and separate collector versus business keys without writing', async () => {
    mount(); fireEvent.click(screen.getByText('Trace operations and SDK onboarding guide'));
    await waitFor(() => expect(screen.getByText(/collector key needs only sources:write/)).toBeVisible());
    expect(screen.getByRole('link', { name: 'Create collector API key' })).toHaveAttribute('href', '/settings?tab=apiKeys&createKey=1&scopes=sources%3Awrite');
    expect(screen.getByText(/Complete cloud inventory/)).toHaveTextContent('sdk/agentteams/node');
    expect(screen.getByText(/collector key needs only sources:write/)).toHaveTextContent('models:write');
    expect(screen.getByText(/Cursors expire after 30 minutes/)).toHaveTextContent('never business');
    expect(agentTeamsTraceApi.get).not.toHaveBeenCalled();
  });
});
