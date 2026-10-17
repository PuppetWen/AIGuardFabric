import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { agentteamsRoleMappingApi as api } from '@/api/agentteamsRoleMapping';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import type { ApiResult } from '@/api/dataSource';
import type { MappingIntent, MappingState } from './types';
import RoleMappingPanel from './RoleMappingPanel';
import { assetId, deferred, intent, requestId, result, state } from './testFixtures';
import { installHarness, mount } from './testHarness';
import { chooseActualMemberAndRole, confirm, consent } from './testInteractions';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('aborts the first catalog request and rejects its late options across a tenant roundtrip', async () => {
  const pending = deferred<ApiResult<MappingState>>(); vi.mocked(api.state).mockReturnValueOnce(pending.promise);
  mount(<RoleMappingPanel />); await waitFor(() => expect(api.state).toHaveBeenCalledTimes(1)); const signal = vi.mocked(api.state).mock.calls[0][0];
  vi.mocked(api.state).mockResolvedValue(result(state({ workers: [], roles: [] })));
  act(() => { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 });
    useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 3 }); });
  await waitFor(() => expect(api.state).toHaveBeenCalledTimes(2)); await act(async () => pending.resolve(result(state())));
  expect(signal?.aborted).toBe(true); expect(screen.queryByText(/Saved tenant viewer/)).not.toBeInTheDocument();
});

it.each(['tenant', 'session', 'tenant-roundtrip'])('clears draft and rejects late save results across a %s change', async change => {
  const pending = deferred<ApiResult<MappingIntent>>(), save = vi.spyOn(api, 'save').mockReturnValue(pending.promise);
  mount(<RoleMappingPanel />); await screen.findByRole('combobox', { name: 'Inventoried Worker / Team / CloudRole' }); await chooseActualMemberAndRole();
  fireEvent.click(consent()); fireEvent.click(screen.getByRole('button', { name: 'Adopt Role constraint manually' })); await confirm('Confirm adoption', false);
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1)); const signal = save.mock.calls[0][2];
  vi.mocked(api.state).mockResolvedValue(result(state({ workers: [], roles: [] })));
  act(() => { if (change === 'session') useAuthStore.setState({ sessionGeneration: 2 });
    else { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 });
      if (change === 'tenant-roundtrip') useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 3 }); } });
  await act(async () => pending.resolve(result(intent({ requestId: save.mock.calls[0][1].request_id }))));
  expect(signal?.aborted).toBe(true); expect(screen.queryByText('Original Role submission fact')).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Original Role request UUID' })).toHaveValue(''); expect(screen.queryByRole('combobox', { name: 'Actual platform Role UUID' })).not.toBeInTheDocument();
});

it('retains the exact early recovery input and focus as the first catalog GET finishes, then reads UUIDv7 only by explicit GET', async () => {
  const pending = deferred<ApiResult<MappingState>>(); vi.mocked(api.state).mockReturnValueOnce(pending.promise);
  const read = vi.spyOn(api, 'receipt').mockResolvedValue(result(intent())), save = vi.spyOn(api, 'save'); mount(<RoleMappingPanel />);
  const input = screen.getByRole('textbox', { name: 'Original Role request UUID' }); fireEvent.change(input, { target: { value: requestId } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Receipt Worker asset UUID' }), { target: { value: assetId } }); act(() => input.focus());
  await act(async () => pending.resolve(result(state()))); await screen.findByRole('combobox', { name: 'Inventoried Worker / Team / CloudRole' });
  expect(input.isConnected).toBe(true); expect(screen.getByRole('textbox', { name: 'Original Role request UUID' })).toBe(input); expect(input).toHaveValue(requestId); expect(input).toHaveFocus();
  expect(read).not.toHaveBeenCalled(); expect(save).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: 'Read original Role receipt (no redispatch)' }));
  await screen.findByText('Original Role submission fact'); expect(read).toHaveBeenCalledWith(assetId, requestId, expect.any(AbortSignal)); expect(save).not.toHaveBeenCalled();
});

it('aborts and discards a late receipt after session replacement without repeating a write', async () => {
  const pending = deferred<ApiResult<MappingIntent>>(), read = vi.spyOn(api, 'receipt').mockReturnValue(pending.promise), save = vi.spyOn(api, 'save');
  mount(<RoleMappingPanel />); fireEvent.change(screen.getByRole('textbox', { name: 'Receipt Worker asset UUID' }), { target: { value: assetId } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Original Role request UUID' }), { target: { value: requestId } });
  fireEvent.click(screen.getByRole('button', { name: 'Read original Role receipt (no redispatch)' })); await waitFor(() => expect(read).toHaveBeenCalledTimes(1));
  const signal = read.mock.calls[0][2]; act(() => useAuthStore.setState({ sessionGeneration: 2 }));
  await act(async () => pending.resolve(result(intent()))); expect(signal?.aborted).toBe(true);
  expect(screen.queryByText('Original Role submission fact')).not.toBeInTheDocument(); expect(save).not.toHaveBeenCalled();
});

it('blocks duplicate submission while waiting and lets explicit original GET own the receipt ahead of a late PUT reply', async () => {
  const pending = deferred<ApiResult<MappingIntent>>(), save = vi.spyOn(api, 'save').mockReturnValue(pending.promise);
  const read = vi.spyOn(api, 'receipt').mockImplementation(async (asset, request) => result(intent({ assetId: asset, requestId: request,
    original: { ...intent().original, version: 10 } })));
  mount(<RoleMappingPanel />); await screen.findByRole('combobox', { name: 'Inventoried Worker / Team / CloudRole' }); await chooseActualMemberAndRole();
  fireEvent.click(consent()); fireEvent.click(screen.getByRole('button', { name: 'Adopt Role constraint manually' })); await confirm('Confirm adoption', false);
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1)); expect(screen.getByRole('button', { name: 'Adopt Role constraint manually' })).toBeDisabled();
  expect(screen.getByRole('combobox', { name: 'Actual platform Role UUID' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Read original Role receipt (no redispatch)' })); await screen.findByText('Original Role submission fact');
  expect(read).toHaveBeenCalledWith(assetId, save.mock.calls[0][1].request_id, expect.any(AbortSignal));
  await act(async () => pending.resolve(result(intent({ requestId: save.mock.calls[0][1].request_id, original: { ...intent().original, version: 1 } }))));
  expect(screen.getByText('10')).toBeInTheDocument(); expect(save).toHaveBeenCalledTimes(1);
});
