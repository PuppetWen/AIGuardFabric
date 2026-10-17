import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { cloudApi, type CloudConfig } from '@/api/cloud';
import { ApiRequestError } from '@/api/transport';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import type { ApiResult } from '@/api/dataSource';
import ConfigurationBinding from './ConfigurationBinding';
import { config, deferred, result } from './testFixtures';
import { installHarness, mount } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();
const consent = 'Confirm public-field management, preserving private configuration; streaming and shared-resource impact remain unknown';

it('uses actual configuration CAS, preserves unknown settings and does not supply or clear secrets', async () => {
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(config()));
  const saved = vi.spyOn(cloudApi, 'save').mockResolvedValue(result(config(2))), callback = vi.fn(); mount(<ConfigurationBinding onSaved={callback} />);
  const input = await screen.findByRole('textbox', { name: 'Model API ID' }); fireEvent.change(input, { target: { value: 'actual-new-api' } });
  expect(screen.getByRole('button', { name: 'Save APIG configuration binding' })).toBeDisabled(); fireEvent.click(screen.getByRole('checkbox', { name: consent }));
  fireEvent.click(screen.getByRole('button', { name: 'Save APIG configuration binding' }));
  await waitFor(() => expect(saved).toHaveBeenCalledWith('alicloud-apig', expect.objectContaining({ expected_version: 1, secrets: {}, clear_secrets: [],
    settings: expect.objectContaining({ configuration_kind: 'content', configuration_http_api_id: 'actual-new-api', custom_preserved: 'user-owned-value', managed_configuration_confirmed: true }) })));
  expect(callback).toHaveBeenCalledTimes(1);
});
it('a save conflict preserves draft and old CAS; latest GET compares and explicit adoption alone changes it', async () => {
  const latest = { ...config(4), settings: { ...config(4).settings, configuration_http_api_id: 'latest-api' } };
  vi.spyOn(cloudApi, 'configuration').mockResolvedValueOnce(result(config())).mockResolvedValue(result(latest));
  const saved = vi.spyOn(cloudApi, 'save').mockRejectedValue(new ApiRequestError('Configuration revision conflict', 409, 'conflict', false));
  mount(<ConfigurationBinding onSaved={vi.fn()} />); const input = await screen.findByRole('textbox', { name: 'Model API ID' });
  fireEvent.change(input, { target: { value: 'retained-draft-api' } }); fireEvent.click(screen.getByRole('checkbox', { name: consent }));
  fireEvent.click(screen.getByRole('button', { name: 'Save APIG configuration binding' })); await screen.findByText('Configuration revision conflict');
  expect(input).toHaveValue('retained-draft-api'); expect(screen.getByText('Save uses configuration version 1')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Read latest APIG configuration to compare (GET)' })); await screen.findByRole('textbox', { name: 'Latest APIG binding comparison' });
  expect(input).toHaveValue('retained-draft-api'); expect(saved).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Explicitly adopt latest APIG binding' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Confirm adopting latest binding' }));
  await waitFor(() => expect(input).toHaveValue('latest-api')); expect(screen.getByText('Save uses configuration version 4')).toBeInTheDocument();
  expect(screen.getByRole('checkbox', { name: consent })).not.toBeChecked(); expect(saved).toHaveBeenCalledTimes(1);
});
it('does not select kind or save a Mock example automatically and changing its target clears consent', async () => {
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result({ ...config(0), settings: {} })); const saved = vi.spyOn(cloudApi, 'save');
  mount(<ConfigurationBinding onSaved={vi.fn()} />); const example = await screen.findByRole('button', { name: 'Explicitly fill the owned Mock example for this kind (no save)' });
  expect(example).toBeDisabled(); fireEvent.click(screen.getByRole('radio', { name: 'Existing model configuration' })); fireEvent.click(example);
  expect(screen.getByRole('textbox', { name: 'Model API ID' })).toHaveValue('api-owned'); expect(saved).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('checkbox', { name: consent })); fireEvent.change(screen.getByRole('textbox', { name: 'APIG target region' }), { target: { value: 'actual-region' } });
  expect(screen.getByRole('checkbox', { name: consent })).not.toBeChecked();
});
it('does not publish a late save callback into another session', async () => {
  const pending = deferred<ApiResult<CloudConfig>>(); vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(config()));
  const saved = vi.spyOn(cloudApi, 'save').mockReturnValue(pending.promise), callback = vi.fn(); mount(<ConfigurationBinding onSaved={callback} />);
  await screen.findByRole('textbox', { name: 'Model API ID' }); fireEvent.click(screen.getByRole('checkbox', { name: consent }));
  fireEvent.click(screen.getByRole('button', { name: 'Save APIG configuration binding' })); await waitFor(() => expect(saved).toHaveBeenCalledTimes(1));
  act(() => useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 }));
  await act(async () => { pending.resolve(result(config(5))); }); expect(callback).not.toHaveBeenCalled();
  expect(screen.queryByText('Save uses configuration version 5')).not.toBeInTheDocument();
});
