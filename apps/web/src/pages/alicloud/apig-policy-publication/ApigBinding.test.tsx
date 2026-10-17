import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { cloudApi, type CloudConfig } from '@/api/cloud';
import type { ApiResult } from '@/api/dataSource';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import ApigBinding from './ApigBinding';
import { config, deferred, result } from './testFixtures';
import { installHarness, mount } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();
const consent = () => screen.getByRole('checkbox', { name: /Confirm management of this existing independent policy/ });
const saveButton = () => screen.getByRole('button', { name: /Save APIG five-ID binding$/ });

it('requires explicit Mock fill and renewed management consent after ID or mode edits', async () => {
  const blank = { ...config(), settings: {} }; vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(blank));
  const save = vi.spyOn(cloudApi, 'save').mockResolvedValue(result(config(2))), onSaved = vi.fn();
  mount(<ApigBinding onSaved={onSaved} />); const policy = await screen.findByRole('textbox', { name: 'Independent policy ID' });
  expect(policy).toHaveValue(''); expect(saveButton()).toBeDisabled(); expect(save).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Explicitly fill the owned Mock five-ID example (no save)' }));
  expect(policy).toHaveValue('policy-agf-demo'); expect(consent()).not.toBeChecked(); expect(save).not.toHaveBeenCalled();
  fireEvent.click(consent()); fireEvent.change(policy, { target: { value: 'actual-policy-owned' } }); expect(consent()).not.toBeChecked();
  fireEvent.click(consent()); fireEvent.click(screen.getByRole('checkbox', { name: 'Configure Mock mode' })); expect(consent()).not.toBeChecked();
  fireEvent.click(consent()); fireEvent.click(saveButton()); await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
  expect(save).toHaveBeenCalledWith('alicloud-apig', expect.objectContaining({ expected_version: 1, mock: false, settings: expect.objectContaining({ policy_id: 'actual-policy-owned', managed_policy_confirmed: true }), secrets: {}, clear_secrets: [] }));
});
it('retains 409 draft and original CAS during GET comparison; adopting a new revision requires explicit confirmation and a new manual save', async () => {
  vi.spyOn(cloudApi, 'configuration').mockResolvedValueOnce(result(config())).mockResolvedValue(result(config(8)));
  const save = vi.spyOn(cloudApi, 'save').mockRejectedValueOnce(new Error('Configuration revision conflict')).mockResolvedValue(result(config(9)));
  mount(<ApigBinding onSaved={vi.fn()} />);
  const input = await screen.findByRole('textbox', { name: 'Independent policy ID' }); fireEvent.change(input, { target: { value: 'unsaved-owned-policy' } });
  fireEvent.click(consent()); fireEvent.click(saveButton()); await screen.findByText('Configuration revision conflict');
  fireEvent.click(screen.getByRole('button', { name: /Read latest APIG configuration to compare/ })); await screen.findByText('Draft / latest configuration revision: 1 / 8');
  expect(input).toHaveValue('unsaved-owned-policy'); expect(screen.getByText('Save uses configuration version 1')).toBeInTheDocument(); expect(save).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Explicitly adopt latest APIG binding' }));
  const confirm = await screen.findByRole('button', { name: 'Confirm adopting latest binding' });
  await waitFor(() => { expect(confirm).toBeVisible(); expect(confirm).toBeEnabled(); }); fireEvent.click(confirm);
  await screen.findByText('Save uses configuration version 8'); expect(input).toHaveValue('policy-agf-demo'); expect(consent()).not.toBeChecked(); expect(save).toHaveBeenCalledTimes(1);
  fireEvent.click(consent()); await waitFor(() => expect(saveButton()).toBeEnabled()); fireEvent.click(saveButton());
  await waitFor(() => expect(save).toHaveBeenCalledTimes(2)); expect(save).toHaveBeenLastCalledWith('alicloud-apig', expect.objectContaining({ expected_version: 8 }));
});
it('does not publish a late binding save or parent callback after a tenant roundtrip', async () => {
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(config()));
  const pending = deferred<ApiResult<CloudConfig>>(), save = vi.spyOn(cloudApi, 'save').mockReturnValue(pending.promise), callback = vi.fn();
  mount(<ApigBinding onSaved={callback} />); await screen.findByRole('textbox', { name: 'Independent policy ID' });
  fireEvent.click(consent()); fireEvent.click(saveButton()); await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  act(() => { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 });
    useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 3 }); });
  await act(async () => { pending.resolve(result(config(9))); }); expect(callback).not.toHaveBeenCalled();
  expect(screen.queryByText('Save uses configuration version 9')).not.toBeInTheDocument();
});
it('aborts an explicit comparison on unmount and discards its late result', async () => {
  const pending = deferred<ApiResult<CloudConfig>>();
  const read = vi.spyOn(cloudApi, 'configuration').mockResolvedValueOnce(result(config())).mockReturnValue(pending.promise);
  const view = mount(<ApigBinding onSaved={vi.fn()} />); await screen.findByRole('textbox', { name: 'Independent policy ID' });
  fireEvent.click(screen.getByRole('button', { name: /Read latest APIG configuration to compare/ })); await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
  const signal = read.mock.calls[1][1]; view.unmount(); expect(signal?.aborted).toBe(true);
  await act(async () => { pending.resolve(result(config(8))); }); expect(screen.queryByText(/latest configuration revision: 1 \/ 8/)).not.toBeInTheDocument();
});
