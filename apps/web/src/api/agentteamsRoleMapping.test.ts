import { expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { agentteamsRoleMappingApi as api } from './agentteamsRoleMapping';
import type { MappingInput } from '@/pages/alicloud/agentteams-role-mapping/types';
vi.mock('./transport', () => ({ callApi: vi.fn() }));

it('uses direct local DTOs, explicit CAS/intent body, GET receipts and no fixture fallback', () => {
  const signal = new AbortController().signal, body: MappingInput = { request_id: '01921d34-0000-7000-8000-000000000001',
    expected_version: 7, confirm_local_constraint: true, change: { action: 'disable' } };
  api.state(signal); api.current('asset/explicit', signal); api.save('asset/explicit', body, signal); api.receipt('asset/explicit', 'intent/explicit', signal);
  expect(callApi).toHaveBeenNthCalledWith(1, '/api/v1/alicloud/agentteams/role-mappings', expect.any(Function), { noFallback: true, signal });
  expect(callApi).toHaveBeenNthCalledWith(2, '/api/v1/alicloud/agentteams/role-mappings/asset%2Fexplicit', expect.any(Function), { noFallback: true, signal });
  expect(callApi).toHaveBeenNthCalledWith(3, '/api/v1/alicloud/agentteams/role-mappings/asset%2Fexplicit', expect.any(Function), { method: 'PUT', body, noFallback: true, signal });
  expect(callApi).toHaveBeenNthCalledWith(4, '/api/v1/alicloud/agentteams/role-mappings/asset%2Fexplicit/requests/intent%2Fexplicit', expect.any(Function), { noFallback: true, signal });
  expect(() => vi.mocked(callApi).mock.calls[0][1]()).toThrow('require the server');
});
