import { expect, it } from 'vitest';
import { configurationSettings, initialNamespace } from './configurationSettings';
it('preserves an explicitly chosen empty default namespace while other empty settings remain absent', () => {
  expect(initialNamespace({})).toBeUndefined();
  expect(initialNamespace({ namespace_id: '' })).toBe('default');
  expect(configurationSettings('alicloud-mse', { namespace_id: 'old', account_id: 'owner' },
    { instance_id: ' instance-owned ', endpoint: '', account_id: '' }, 'default'))
    .toEqual({ instance_id: 'instance-owned', namespace_id: '' });
  expect(configurationSettings('alicloud-agentteams', {}, { instance_id: 'a', namespace_id: '', endpoint: '' }))
    .toEqual({ instance_id: 'a' });
});
it('never treats an unselected namespace, empty specific ID or blank instance as a usable default', () => {
  expect(() => configurationSettings('alicloud-mse', {}, { instance_id: 'mse' })).toThrow(/Select the default/);
  expect(() => configurationSettings('alicloud-mse', {}, { instance_id: 'mse', namespace_id: ' ' }, 'specific')).toThrow(/Select the default/);
  expect(() => configurationSettings('alicloud-mse', {}, { instance_id: ' ', namespace_id: '' }, 'default')).toThrow(/instance ID is required/);
  expect(configurationSettings('alicloud-mse', {}, { instance_id: 'mse', namespace_id: ' ns-owned ' }, 'specific'))
    .toEqual({ instance_id: 'mse', namespace_id: 'ns-owned' });
});
