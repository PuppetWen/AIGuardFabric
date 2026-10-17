import { expect, it } from 'vitest';
import { apigAuthorizationSettings } from './configurationAuthorization';
import { config } from '../apig-configuration-publication/testFixtures';
function snapshot() { const row = config(); return { ...row, settings: { ...row.settings, managed_policy_confirmed: true, policy_id: 'actual-policy' } }; }
it.each(['credentials', 'clear', 'mode', 'source'])('clears both kinds of consent when %s authority changes', change => {
  const row = snapshot(), settings = { ...row.settings, ...(change === 'source' ? { account_id: 'another-account' } : {}) };
  const result = apigAuthorizationSettings(row, settings, change === 'mode' ? !row.mock : row.mock,
    change === 'credentials' ? { access_key_id: 'synthetic-new-key' } : {}, change === 'clear' ? ['access_key_id'] : []);
  expect(result.managed_policy_confirmed).toBe(false); expect(result.managed_configuration_confirmed).toBe(false);
  expect(result.custom_preserved).toBe('user-owned-value');
});
it('changing a configuration tuple clears only its consent and preserves independent rate-limit consent', () => {
  const row = snapshot(), settings = { ...row.settings, configuration_http_api_id: 'another-actual-api' };
  const result = apigAuthorizationSettings(row, settings, row.mock, {}, []);
  expect(result.managed_configuration_confirmed).toBe(false); expect(result.managed_policy_confirmed).toBe(true);
});
it('an independent policy tuple does not clear unchanged configuration consent', () => {
  const row = snapshot(), settings = { ...row.settings, policy_id: 'another-policy' };
  const result = apigAuthorizationSettings(row, settings, row.mock, {}, []);
  expect(result.managed_policy_confirmed).toBe(false); expect(result.managed_configuration_confirmed).toBe(true);
});
it('unchanged settings preserve both consents without dropping unknown user settings', () => {
  const row = snapshot(); expect(apigAuthorizationSettings(row, row.settings, row.mock, {}, [])).toEqual(row.settings);
});
