import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ConfigProvider } from 'antd';
import type { ReactNode } from 'react';
import { cloudApi, type CloudConfig } from '@/api/cloud';
import { ApiRequestError } from '@/api/transport';
import { useAuthStore } from '@/stores/authStore';
import { useSessionAccess } from '@/api/sessionAccess';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import CloudEditor from '../CloudEditor';
import { publicationAuthorizationSettings, validOptionalEngineOrigin } from './configurationAuthorization';
import { configurationSettings } from '../mse/configurationSettings';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
vi.mock('../CloudOperations', () => ({ default: () => null }));
vi.mock('../CloudInventory', () => ({ CloudInventory: () => null }));
const original = useAuthStore.getState();
const result = <T,>(data: T) => ({ data, meta: { source: 'live' as const, elapsedMs: 1, at: Date.now() } });
const snapshot = (): CloudConfig => ({ name: 'alicloud-mse', displayName: 'Owned MSE', version: 1, enabled: true, environmentMock: false, mock: false,
  endpoint: 'https://mse.example.test', operations: [], secretKeys: ['access_key_id', 'access_key_secret'],
  settings: { endpoint: 'https://preserved-openapi.example.test', region_id: 'explicit-region', instance_id: 'explicit-instance',
    engine_origin: 'https://engine.example.test', config_group: 'AGF', config_data_id: 'owned-policy.json', config_dialect: 'nacos-http-v2-cas',
    credential_source: 'access-key', namespace_id: '', inventory_marker: 'retain', managed_upsert_confirmed: true } });
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 1 });
  vi.mocked(useSessionAccess).mockReturnValue({ has: () => true, isLoading: false } as unknown as ReturnType<typeof useSessionAccess>);
});
afterEach(async () => { cleanup(); vi.restoreAllMocks(); useAuthStore.setState(original); await act(async () => { await i18n.changeLanguage('zh-CN'); }); });
function mount(node: ReactNode) { return render(<ConfigProvider theme={{ token: { motion: false } }}>{node}</ConfigProvider>); }

it('clears stale publication authorization for source, tuple, mode and credential changes while preserving unchanged settings', () => {
  const original = snapshot(), unchanged = { ...original.settings };
  expect(publicationAuthorizationSettings(original, unchanged, false, { access_key_id: '' }, [])).toBe(unchanged);
  for (const patch of [{ engine_origin: 'https://new.example.test' }, { namespace_id: 'explicit-other' }, { account_id: 'other-source' },
    { ecs_role_name: 'different-role' }, { oidc_provider_arn: 'different-provider' }])
    expect(publicationAuthorizationSettings(original, { ...unchanged, ...patch }, false, {}, []).managed_upsert_confirmed).toBe(false);
  expect(publicationAuthorizationSettings(original, unchanged, true, {}, []).managed_upsert_confirmed).toBe(false);
  expect(publicationAuthorizationSettings(original, unchanged, false, { security_token: 'synthetic-rotation' }, []).managed_upsert_confirmed).toBe(false);
  expect(publicationAuthorizationSettings(original, unchanged, false, {}, ['access_key_secret']).managed_upsert_confirmed).toBe(false);
  expect(unchanged.managed_upsert_confirmed).toBe(true);
  expect(validOptionalEngineOrigin('')).toBe(true); expect(validOptionalEngineOrigin('https://engine.example.test')).toBe(true);
  expect(validOptionalEngineOrigin('https://engine.example.test/path')).toBe(false); expect(validOptionalEngineOrigin('https://user:synthetic@engine.example.test')).toBe(false);
  expect(validOptionalEngineOrigin('http://192.168.1.2')).toBe(false); expect(validOptionalEngineOrigin('http://127.0.0.1:1234')).toBe(true);
});
it('clears authorization when an unchanged form removes an empty source identity but keeps the explicit default namespace', () => {
  const original = snapshot(); original.settings.account_id = '';
  const merged = configurationSettings(original.name, original.settings, { account_id: '' }, 'default');
  expect(merged.account_id).toBeUndefined(); expect(merged.namespace_id).toBe('');
  const authorized = publicationAuthorizationSettings(original, merged, false, {}, []);
  expect(authorized.managed_upsert_confirmed).toBe(false);
  expect(authorized.config_data_id).toBe('owned-policy.json'); expect(original.settings.managed_upsert_confirmed).toBe(true);
});
it('saves a separate new engine origin with explicitly supplied credentials, clears confirmation and retains the default namespace and other settings', async () => {
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(snapshot()));
  const save = vi.spyOn(cloudApi, 'save').mockResolvedValue(result({ ...snapshot(), version: 2 }));
  mount(<CloudEditor name="alicloud-mse" onClose={vi.fn()} onSaved={vi.fn()} />);
  fireEvent.change(await screen.findByRole('textbox', { name: 'Nacos engine origin (optional for dedicated publication)' }), { target: { value: 'https://new-engine.example.test' } });
  fireEvent.change(screen.getByLabelText('AccessKey ID', { selector: 'input[type="password"]' }), { target: { value: 'synthetic-key' } });
  fireEvent.change(screen.getByLabelText('AccessKey Secret', { selector: 'input[type="password"]' }), { target: { value: 'synthetic-secret' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save configuration' }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  expect(save).toHaveBeenCalledWith('alicloud-mse', expect.objectContaining({ enabled: true, mock: false, expected_version: 1,
    settings: expect.objectContaining({ engine_origin: 'https://new-engine.example.test', namespace_id: '', config_data_id: 'owned-policy.json',
      endpoint: snapshot().settings.endpoint, inventory_marker: 'retain', managed_upsert_confirmed: false }),
    secrets: expect.objectContaining({ access_key_id: 'synthetic-key', access_key_secret: 'synthetic-secret' }) }));
});
it('retains existing upsert authorization on an unchanged metadata save and leaves engine origin optional for inventory-only configuration', async () => {
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(snapshot()));
  const save = vi.spyOn(cloudApi, 'save').mockRejectedValue(new Error('Keep editor open'));
  mount(<CloudEditor name="alicloud-mse" onClose={vi.fn()} onSaved={vi.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Save configuration' })); await screen.findByText('Keep editor open');
  expect(save).toHaveBeenCalledWith('alicloud-mse', expect.objectContaining({ settings: expect.objectContaining({ managed_upsert_confirmed: true, namespace_id: '' }) }));
  // Clearing an optional origin is a deliberate unbinding, not a mandatory-field validation error.
  fireEvent.change(screen.getByRole('textbox', { name: 'Nacos engine origin (optional for dedicated publication)' }), { target: { value: '' } });
  const ready = screen.getByRole('button', { name: /Save configuration$/ }); await waitFor(() => expect(ready).not.toHaveClass('ant-btn-loading')); fireEvent.click(ready);
  await waitFor(() => expect(save).toHaveBeenCalledTimes(2));
  const body = save.mock.calls[1][1] as { settings: Record<string, unknown> };
  expect(body.settings.engine_origin).toBeUndefined(); expect(body.settings.managed_upsert_confirmed).toBe(false);
});
it.each([401, 409])('keeps the engine and credential draft after HTTP %s without a version bump or automatic save', async status => {
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(snapshot()));
  const save = vi.spyOn(cloudApi, 'save').mockRejectedValue(new ApiRequestError('Synthetic save rejection', status, 'synthetic', false)), onSaved = vi.fn();
  mount(<CloudEditor name="alicloud-mse" onClose={vi.fn()} onSaved={onSaved} />);
  const origin = await screen.findByRole('textbox', { name: 'Nacos engine origin (optional for dedicated publication)' });
  fireEvent.change(origin, { target: { value: 'https://draft-engine.example.test' } });
  const secret = screen.getByLabelText('AccessKey Secret', { selector: 'input[type="password"]' }); fireEvent.change(secret, { target: { value: 'synthetic-draft-secret' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save configuration' })); await screen.findByText('Synthetic save rejection');
  expect(origin).toHaveValue('https://draft-engine.example.test'); expect(secret).toHaveValue('synthetic-draft-secret');
  expect(save).toHaveBeenCalledTimes(1); expect(save).toHaveBeenCalledWith('alicloud-mse', expect.objectContaining({ expected_version: 1 })); expect(onSaved).not.toHaveBeenCalled();
});
