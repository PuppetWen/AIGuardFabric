import { expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { agentteamsOrchestrationApi as api } from './agentteamsOrchestration';
import { camelizeDeep } from './contract';
import { definition } from '@/pages/alicloud/agentteams-orchestration/testFixtures';
import type { Input } from '@/pages/alicloud/agentteams-orchestration/types';
vi.mock('./transport', () => ({ callApi: vi.fn() }));

it('uses pure GETs, explicit immutable body and URI encoding without fixture fallback', () => {
  const signal = new AbortController().signal, body: Input = { request_id: '10000000-0000-5000-8000-000000000002', expected_version: 3,
    configuration_version: 1, inventory_fingerprint: 'a'.repeat(64), change: { action: 'save_definition', definition: definition() },
    confirm_application_owned: true, confirm_mock_sync: false, confirm_source_change: false };
  api.state(signal); api.current('Team / actual', signal); api.preview('Team / actual', body, signal); api.apply('Team / actual', body, signal); api.receipt('id/actual', signal);
  const opts = { noFallback: true, signal, opaqueKeys: ['local', 'receiver', 'template', 'definition'] };
  expect(callApi).toHaveBeenNthCalledWith(1, '/api/v1/alicloud/agentteams/orchestration-definitions', expect.any(Function), opts);
  expect(callApi).toHaveBeenNthCalledWith(2, '/api/v1/alicloud/agentteams/orchestration-definitions/teams/Team%20%2F%20actual', expect.any(Function), opts);
  expect(callApi).toHaveBeenNthCalledWith(3, '/api/v1/alicloud/agentteams/orchestration-definitions/teams/Team%20%2F%20actual/preview', expect.any(Function), { ...opts, method: 'POST', body });
  expect(callApi).toHaveBeenNthCalledWith(4, '/api/v1/alicloud/agentteams/orchestration-definitions/teams/Team%20%2F%20actual', expect.any(Function), { ...opts, method: 'PUT', body });
  expect(callApi).toHaveBeenNthCalledWith(5, '/api/v1/alicloud/agentteams/orchestration-definitions/requests/id%2Factual', expect.any(Function), opts);
  expect(() => vi.mocked(callApi).mock.calls[0][1]()).toThrow('server');
});

it('preserves imported snake-case DAG field names while mapping surrounding safe DTO fields', () => {
  const result = camelizeDeep({ team_name: 'Team', local: definition(), template: definition() }, ['local', 'receiver', 'template', 'definition']);
  expect(result).toEqual({ teamName: 'Team', local: definition(), template: definition() });
});
