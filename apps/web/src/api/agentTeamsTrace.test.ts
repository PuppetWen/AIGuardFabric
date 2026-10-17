import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiRequestError, callApi } from './transport';
import type * as Transport from './transport';
import { agentTeamsTraceApi } from './agentTeamsTrace';
import { traceFixture, traceMeta, traceWindow, unavailableTrace } from '@/pages/alicloud/trace/traceFixtures';

vi.mock('./transport', async () => ({ ...await vi.importActual<typeof Transport>('./transport'), callApi: vi.fn() }));
afterEach(() => vi.clearAllMocks());

describe('Trace evidence API contract', () => {
  it('makes only GET with explicit RFC3339 bounds, opaque cursor, abort and no demo fallback', async () => {
    const query = { ...traceWindow, traceId: 'sdk:observed-root.1' };
    const data = { ...traceFixture(), traceId: query.traceId };
    vi.mocked(callApi).mockResolvedValue({ data, meta: traceMeta });
    const abort = new AbortController();
    expect((await agentTeamsTraceApi.get(query, 'opaque+cursor/', abort.signal)).data).toEqual(data);
    expect(callApi).toHaveBeenCalledWith('/api/v1/alicloud/agentteams/traces/sdk%3Aobserved-root.1', expect.any(Function),
      { method: 'GET', query: { from: query.from, until: query.until, limit: 50, cursor: 'opaque+cursor/' },
        signal: abort.signal, noFallback: true });
    const fallback = vi.mocked(callApi).mock.calls[0][1];
    expect(() => fallback()).toThrow(/backend/);
  });
  it('preserves unknown inventory and a valid observed-empty scope as different states', async () => {
    vi.mocked(callApi).mockResolvedValueOnce({ data: unavailableTrace(), meta: traceMeta })
      .mockResolvedValueOnce({ data: traceFixture(0), meta: traceMeta });
    expect((await agentTeamsTraceApi.get(traceWindow)).data.totalEvents).toBeNull();
    expect((await agentTeamsTraceApi.get(traceWindow)).data.totalEvents).toBe(0);
  });
  it.each(['tree', 'authorized', 'edge', 'count', 'cap'] as const)('rejects invented or inconsistent %s evidence', async kind => {
    const data = traceFixture();
    if (kind === 'tree') data.complete = true as false;
    if (kind === 'authorized') data.graph.nodes[0].authorized = true as unknown as null;
    if (kind === 'edge') data.graph.edges[0].toNodeId = 'unobserved-node';
    if (kind === 'count') data.totalEvents = null;
    if (kind === 'cap') data.graph.nodes = Array.from({ length: 2001 }, () => data.graph.nodes[0]);
    vi.mocked(callApi).mockResolvedValue({ data, meta: traceMeta });
    await expect(agentTeamsTraceApi.get(traceWindow)).rejects.toMatchObject({ status: 502, code: 'trace_contract', fallbackable: false });
  });
  it('passes a cursor conflict through without querying or creating fallback events again', async () => {
    vi.mocked(callApi).mockRejectedValue(new ApiRequestError('Snapshot changed', 409, 'conflict', false));
    await expect(agentTeamsTraceApi.get(traceWindow, 'old-cursor')).rejects.toMatchObject({ status: 409 });
    expect(callApi).toHaveBeenCalledTimes(1);
  });
});
