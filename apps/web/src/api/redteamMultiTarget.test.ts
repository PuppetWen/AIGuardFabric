import { afterEach, expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { multiTargetApi } from './redteamMultiTarget';
vi.mock('./transport', () => ({ callApi: vi.fn() }));
afterEach(() => vi.clearAllMocks());
it('recent lookup and transport comparison are pure; archive captures exact generation and approval exact CAS', async () => {
  vi.mocked(callApi).mockResolvedValue({ data: {}, meta: { source: 'live', at: 0, elapsedMs: 0 } });
  const signal = new AbortController().signal;
  await multiTargetApi.recent(20, signal); await multiTargetApi.archive('owned-id', 7, signal); await multiTargetApi.managed('mcp-http', 'owned-id', signal);
  expect(callApi).toHaveBeenNthCalledWith(1, '/api/v1/redteam/multi-target/runs?limit=20&offset=20', expect.any(Function), { noFallback: true, signal });
  expect(callApi).toHaveBeenNthCalledWith(2, '/api/v1/redteam/multi-target/runs/owned-id/archive', expect.any(Function), { method: 'POST', body: { expected_generation: 7 }, noFallback: true, signal });
  expect(callApi).toHaveBeenNthCalledWith(3, '/api/v1/redteam/multi-target/profiles/mcp-http/owned-id/transport', expect.any(Function), { noFallback: true, signal });
  const body = { expected_version: 3, profile_version: 7, url: 'http://10.0.0.4:8080/mcp', enabled: true, mcp_protocol_revision: '2025-11-25' as const, private_network: { addresses: ['10.0.0.4'], port: 8080, allow_plain_http: true, confirm_exact_private_network: true } };
  await multiTargetApi.saveManaged('mcp-http', 'owned-id', body, signal);
  expect(callApi).toHaveBeenNthCalledWith(4, '/api/v1/redteam/multi-target/profiles/mcp-http/owned-id/transport', expect.any(Function), { method: 'PUT', body, noFallback: true, signal });
});
it('receipt lookup is GET without fallback while recovery sends only the strict empty local body', async () => {
  vi.mocked(callApi).mockResolvedValue({ data: {}, meta: { source: 'live', at: 0, elapsedMs: 0 } });
  const signal = new AbortController().signal; await multiTargetApi.get('owned-id', signal); await multiTargetApi.local('owned-id', 'recover', signal);
  expect(callApi).toHaveBeenNthCalledWith(1, '/api/v1/redteam/multi-target/runs/owned-id', expect.any(Function), { noFallback: true, signal });
  expect(callApi).toHaveBeenNthCalledWith(2, '/api/v1/redteam/multi-target/runs/owned-id/recover', expect.any(Function), { method: 'POST', body: {}, noFallback: true, signal });
});
