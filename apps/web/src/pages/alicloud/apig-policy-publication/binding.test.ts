import { expect, it } from 'vitest';
import { apigAuthorizationSettings } from './configurationAuthorization';
import { bindingBody, bindingDraft, fields, mockExample } from './binding';
import { applicable, matchingObservation, unknownReady } from './eligibility';
import { config, observation, operation, operationId, preview, state } from './testFixtures';

it('requires explicit actual IDs and consent without inventing a deployment or trimming its identity', () => {
  const saved = config(), draft = bindingDraft(saved);
  expect(() => bindingBody(saved, draft)).toThrow('confirm');
  for (const id of ['', ' actual-id ', '../policy', 'api/path', 'api\\path', '\u0001api', '中'.repeat(86)]) {
    expect(() => bindingBody(saved, { ...draft, confirmed: true, ids: { ...draft.ids, policy_id: id } })).toThrow('ID');
  }
  const absent = bindingDraft({ ...saved, settings: {} });
  expect(absent.region).toBe(''); expect(fields.every(key => absent.ids[key] === '')).toBe(true);
  expect(() => bindingBody(saved, { ...absent, confirmed: true })).toThrow('ID');
});
it('uses real CAS including first revision zero, preserves user settings and does not create or initialize anything', () => {
  const saved = config(0), body = bindingBody(saved, { ...bindingDraft(saved), confirmed: true });
  expect(body).toMatchObject({ expected_version: 0, secrets: {}, clear_secrets: [], settings: {
    custom_preserved: 'user-owned-value', account_id: 'actual-account-label', managed_policy_confirmed: true,
  } });
  expect(body).not.toHaveProperty('initialize_mock_fixture');
  expect(() => bindingBody({ ...saved, version: NaN }, { ...bindingDraft(saved), confirmed: true })).toThrow('revision');
});
it('explicit Mock fill keeps mode and enabled state but clears prior consent', () => {
  const draft = { ...bindingDraft(config()), enabled: false, mock: false, confirmed: true }, filled = mockExample(draft);
  expect(filled).toMatchObject({ enabled: false, mock: false, confirmed: false, region: 'cn-hangzhou', ids: {
    policy_id: 'policy-agf-demo', policy_http_api_id: 'api-agf-demo', policy_attachment_id: 'attachment-agf-demo',
  } });
});
it('clears only APIG management consent for changed target, source, mode or credentials', () => {
  const saved = config();
  expect(apigAuthorizationSettings(saved, saved.settings, true, {}, [])).toBe(saved.settings);
  expect(apigAuthorizationSettings(saved, { ...saved.settings, credential_source: 'access-key', endpoint_style: 'public', duration_seconds: 3600 }, true, {}, [])
    .managed_policy_confirmed).toBe(true);
  for (const settings of [{ ...saved.settings, policy_id: 'different' }, { ...saved.settings, account_id: '' }, { ...saved.settings, endpoint: 'https://new.example.test' }]) {
    expect(apigAuthorizationSettings(saved, settings, true, {}, [])).toMatchObject({ custom_preserved: 'user-owned-value', managed_policy_confirmed: false });
  }
  expect(apigAuthorizationSettings(saved, saved.settings, false, {}, []).managed_policy_confirmed).toBe(false);
  expect(apigAuthorizationSettings(saved, { ...saved.settings, duration_seconds: 900 }, true, {}, []).managed_policy_confirmed).toBe(false);
  expect(apigAuthorizationSettings(saved, saved.settings, true, { access_key_secret: 'synthetic-test-value' }, []).managed_policy_confirmed).toBe(false);
  expect(apigAuthorizationSettings(saved, saved.settings, true, {}, ['access_key_id']).managed_policy_confirmed).toBe(false);
  expect(apigAuthorizationSettings({ ...saved, name: 'alicloud-mse' }, saved.settings, false, { access_key_id: 'fixture' }, [])).toBe(saved.settings);
});
it('does not apply an expired, consumed, stale-state or already attempted preview', () => {
  const data = state(), candidate = preview(); expect(applicable(data, candidate, null)).toBe(true);
  expect(applicable(data, candidate, candidate.id)).toBe(false);
  expect(applicable(data, { ...candidate, consumedBy: operationId }, null)).toBe(false);
  expect(applicable(data, { ...candidate, expiresAt: new Date(Date.now() - 1).toISOString() }, null)).toBe(false);
  expect(applicable({ ...data, stateVersion: 99 }, candidate, null)).toBe(false);
  expect(matchingObservation(data, observation({ target: { ...candidate.target, configurationVersion: 2 } }))).toBe(false);
});
it('requires locally completed Unknown and both fresh observation times later than its lease', () => {
  const lease = new Date(Date.now() - 10000).toISOString(), fresh = new Date(Date.now() - 1000).toISOString();
  const data = state({ unresolvedOperationId: operationId }), old = operation({ leaseExpiresAt: lease, status: 'uncertain' });
  expect(unknownReady(data, observation({ startedAt: fresh, observedAt: fresh }), old)).toBe(true);
  expect(unknownReady(data, observation({ startedAt: lease, observedAt: fresh }), old)).toBe(false);
  expect(unknownReady(data, observation({ startedAt: fresh, observedAt: fresh }), { ...old, completionState: 'running' })).toBe(false);
});

it('preserves unchanged settings identity and resets only the changed management surface', () => {
  const saved = config();
  const normalized = { ...saved.settings, credential_source: 'access-key', endpoint_style: 'public', duration_seconds: 3600 };
  expect(apigAuthorizationSettings(saved, normalized, true, {}, [])).toBe(normalized);
  const confirmed = { ...saved.settings, managed_configuration_confirmed: true };
  const snapshot = { ...saved, settings: confirmed };
  const policyChange = { ...confirmed, policy_id: 'different-policy' };
  const policyResult = apigAuthorizationSettings(snapshot, policyChange, true, {}, []);
  expect(policyResult).not.toBe(policyChange);
  expect(policyResult).toMatchObject({ managed_policy_confirmed: false, managed_configuration_confirmed: true });
  expect(policyChange).toMatchObject({ managed_policy_confirmed: true });
  const configurationChange = { ...confirmed, configuration_plugin_id: 'different-plugin' };
  expect(apigAuthorizationSettings(snapshot, configurationChange, true, {}, []))
    .toMatchObject({ managed_policy_confirmed: true, managed_configuration_confirmed: false });
});
