import { afterEach, expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { agentTeamsAuditApi } from './agentTeamsAudit';

vi.mock('./transport', () => ({ callApi: vi.fn() }));
afterEach(() => vi.clearAllMocks());

it('keeps version and enabled wire fields and forbids audit demo fallback', () => {
  agentTeamsAuditApi.bind('source/one', 7, true);
  expect(callApi).toHaveBeenCalledWith('/api/v1/alicloud/agentteams/audit-sources/source%2Fone', expect.any(Function),
    { method: 'PUT', body: { expected_version: 7, enabled: true }, noFallback: true });
  agentTeamsAuditApi.events('opaque-cursor');
  expect(callApi).toHaveBeenLastCalledWith('/api/v1/alicloud/agentteams/audit-events', expect.any(Function),
    { query: { limit: 50, cursor: 'opaque-cursor' }, noFallback: true });
  agentTeamsAuditApi.sources();
  expect(callApi).toHaveBeenLastCalledWith('/api/v1/alicloud/agentteams/audit-sources', expect.any(Function), { noFallback: true });
});
