import { afterEach, expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { policiesApi, validPolicyVersion } from './policies';
import { policyBody } from './payloads';
import { policy as adaptPolicy } from './adapters/governance';
import type { Policy } from '@/types/domain';
import { policyFixture, policyResult } from '@/pages/policies/policyTestFixtures';
vi.mock('./transport', () => ({ callApi: vi.fn() }));
afterEach(() => vi.clearAllMocks());

it('keeps creation distinct and preserves scopes/actions while sending an explicit reviewed update revision', async () => {
  const draft = policyFixture(1, { scopeAgentIds: ['agent-owned'], scopeDepartments: ['Finance'], action: 'mask' });
  vi.mocked(callApi).mockResolvedValue(policyResult(policyFixture(2)));
  await policiesApi.save({ ...draft, id: undefined });
  expect(callApi).toHaveBeenLastCalledWith('/api/v1/policies', expect.any(Function), expect.objectContaining({
    method: 'POST', noFallback: true, body: expect.objectContaining({ expected_version: undefined, action: 'redact',
      scope_agent_ids: ['agent-owned'], scope_departments: ['Finance'] }),
  }));
  await policiesApi.save(draft, 7);
  expect(callApi).toHaveBeenLastCalledWith(`/api/v1/policies/${draft.id}`, expect.any(Function), expect.objectContaining({
    method: 'PUT', noFallback: true, body: expect.objectContaining({ expected_version: 7, source: draft.code }),
  }));
  // Existing api.savePolicy uses the same payload helper and therefore carries real version too.
  expect(policyBody(draft)).toMatchObject({ expected_version: 1 });
});
it('refuses missing or invalid editing revisions before dispatch rather than guessing a version', () => {
  for (const revision of [undefined, 0, -1, 1.5, 4_294_967_296]) {
    expect(() => policiesApi.save(policyFixture(), revision)).toThrow(/actual policy revision/);
  }
  expect(callApi).not.toHaveBeenCalled(); expect(validPolicyVersion(4_294_967_295)).toBe(true);
});
it('sends versioned deletion and exact path/body restore, mapping the new actual signed version', async () => {
  const draft = policyFixture(5);
  vi.mocked(callApi).mockResolvedValueOnce(policyResult({ deleted: draft.id }));
  await policiesApi.delete(draft.id, 5);
  expect(callApi).toHaveBeenLastCalledWith(`/api/v1/policies/${draft.id}`, expect.any(Function), {
    method: 'DELETE', query: { expected_version: 5 }, noFallback: true,
  });
  vi.mocked(callApi).mockResolvedValueOnce(policyResult({ policy: { ...draft, version: 6, language: 'structured', structured: { commandDeny: ['unsafe'] } } }));
  const restored = await policiesApi.restore(draft.id, 2, 5);
  expect(callApi).toHaveBeenLastCalledWith(`/api/v1/policies/${draft.id}/versions/2/restore`, expect.any(Function), {
    method: 'POST', noFallback: true, body: { version: 2, expected_version: 5 },
  });
  expect(restored.data).toMatchObject({ version: 6 }); expect(JSON.parse(restored.data.code)).toEqual({ commandDeny: ['unsafe'] });
});
it('reads history and maps the actual revision without defaulting absent revision to one', async () => {
  vi.mocked(callApi).mockResolvedValueOnce(policyResult({ versions: [policyFixture(9), { ...policyFixture(), version: undefined }] }));
  const result = await policiesApi.history('owned');
  expect(callApi).toHaveBeenCalledWith('/api/v1/policies/owned/versions', expect.any(Function), { noFallback: true });
  expect(result.data.versions[0].version).toBe(9); expect(result.data.versions[1].version).toBeUndefined();
});
it.each([['quota', 'quota'], ['circuitbreak', 'circuit-break'], ['approval', 'approval']])(
  'preserves server %s semantics through metadata-only editing and a versioned update', async (action, wireAction) => {
    const original = policyFixture(4), draft = adaptPolicy({ ...original, action, language: 'cel', source: original.code }) as unknown as Policy;
    draft.description = 'Only metadata changed'; vi.mocked(callApi).mockResolvedValue(policyResult({ ...draft, version: 5 }));
    await policiesApi.save(draft, 4);
    expect(callApi).toHaveBeenLastCalledWith(`/api/v1/policies/${draft.id}`, expect.any(Function), expect.objectContaining({
      method: 'PUT', body: expect.objectContaining({ expected_version: 4, action: wireAction, source: original.code, description: 'Only metadata changed' }),
    }));
  },
);
it.each(['future-provider-action', '__proto__'])('keeps unknown %s observable but refuses dispatch instead of substituting audit', action => {
  const draft = adaptPolicy({ ...policyFixture(4), action }) as unknown as Policy;
  expect(draft).toMatchObject({ action: 'unknown', rawAction: action, version: 4 });
  expect(() => policiesApi.save(draft, 4)).toThrow(/Unknown policy action/); expect(callApi).not.toHaveBeenCalled();
});
