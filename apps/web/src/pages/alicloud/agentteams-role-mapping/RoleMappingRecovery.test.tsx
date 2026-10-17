import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { ApiRequestError } from '@/api/transport';
import { agentteamsRoleMappingApi as api } from '@/api/agentteamsRoleMapping';
import type { ApiResult } from '@/api/dataSource';
import type { MappingIntent } from './types';
import RoleMappingPanel from './RoleMappingPanel';
import { assetId, constraint, deferred, intent, result, state } from './testFixtures';
import { installHarness, mount } from './testHarness';
import { chooseActualMemberAndRole, confirm, consent } from './testInteractions';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

async function submit() {
  mount(<RoleMappingPanel />);
  await screen.findByRole('combobox', { name: 'Inventoried Worker / Team / CloudRole' }); await chooseActualMemberAndRole();
  fireEvent.click(consent()); fireEvent.click(screen.getByRole('button', { name: 'Adopt Role constraint manually' })); await confirm('Confirm adoption');
}
const originalRead = () => screen.getByRole('button', { name: /Read original Role receipt \(no redispatch\)/ });

it.each([0, 408, 503, 'invalid-success'] as const)('locks the immutable intent after %s and prevents double-click or compare from issuing a new PUT', async outcome => {
  const save = vi.spyOn(api, 'save');
  if (outcome === 'invalid-success') save.mockResolvedValue(result(intent({ original: constraint({ version: 0 }) })));
  else save.mockRejectedValue(new ApiRequestError('Original result unknown', outcome, 'unknown', false));
  await submit(); await screen.findByText('Original intent retained; new writes are locked');
  const body = save.mock.calls[0][1], adopt = screen.getByRole('button', { name: 'Adopt Role constraint manually' });
  expect(adopt).toBeDisabled(); fireEvent.doubleClick(adopt); expect(save).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('textbox', { name: 'Original Role request UUID' })).toHaveValue(body.request_id);
  expect(screen.getByRole('textbox', { name: 'Original Role request UUID' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Start new local action explicitly' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: /Reload Roles and members to compare/ }));
  await waitFor(() => expect(api.state).toHaveBeenCalledTimes(2));
  expect(screen.getByRole('button', { name: 'Adopt latest comparison explicitly (no save)' })).toBeDisabled();
  expect(save.mock.calls[0][1]).toEqual(body); expect(save).toHaveBeenCalledTimes(1);
});

it('a lost reply and receipt 404 retain the same UUID/CAS; a later trusted GET requires an explicit new action and manual adoption', async () => {
  vi.mocked(api.state).mockResolvedValueOnce(result(state({ items: [constraint({ version: 3 })] })))
    .mockResolvedValue(result(state({ items: [constraint({ version: 7 })] })));
  const save = vi.spyOn(api, 'save').mockRejectedValue(new ApiRequestError('Reply lost', 0, 'network', false));
  const read = vi.spyOn(api, 'receipt').mockRejectedValueOnce(new ApiRequestError('Receipt not found', 404, 'not_found', false))
    .mockImplementation(async (asset, request) => result(intent({ assetId: asset, requestId: request, original: constraint({ version: 4 }) })));
  await submit(); const body = save.mock.calls[0][1];
  fireEvent.click(originalRead()); await screen.findByText('Receipt not found');
  expect(screen.getByRole('button', { name: 'Start new local action explicitly' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Adopt Role constraint manually' })).toBeDisabled();
  expect(consent()).toBeChecked(); expect(save).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: /Reload Roles and members to compare/ }));
  await screen.findByText(/Draft save version \/ current mapping version: 3 \/ 7/);
  expect(screen.getByRole('button', { name: 'Start new local action explicitly' })).toBeDisabled();
  fireEvent.click(originalRead()); await screen.findByText('Original Role submission fact');
  await waitFor(() => expect(screen.getByRole('button', { name: 'Start new local action explicitly' })).toBeEnabled());
  expect(read.mock.calls.map(call => call.slice(0, 2))).toEqual([[assetId, body.request_id], [assetId, body.request_id]]);
  expect(screen.getByText(/Draft save version \/ current mapping version: 3 \/ 7/)).toBeInTheDocument(); expect(save).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Start new local action explicitly' })); await confirm('Confirm new local action');
  expect(consent()).not.toBeChecked(); expect(save).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Adopt latest comparison explicitly (no save)' })); await confirm('Confirm latest adoption');
  save.mockImplementation(async (asset, next) => result(intent({ assetId: asset, requestId: next.request_id })));
  fireEvent.click(consent()); fireEvent.click(screen.getByRole('button', { name: 'Adopt Role constraint manually' })); await confirm('Confirm adoption');
  expect(save).toHaveBeenCalledTimes(2); expect(save.mock.calls[1][1].expected_version).toBe(7); expect(save.mock.calls[1][1].request_id).not.toBe(body.request_id);
});

it('an explicit GET may resolve an in-flight PUT; duplicate clicks and a later inconclusive reply cannot overwrite that receipt or reopen writes', async () => {
  const pending = deferred<ApiResult<MappingIntent>>(), save = vi.spyOn(api, 'save').mockReturnValue(pending.promise);
  const read = vi.spyOn(api, 'receipt').mockImplementation(async (asset, request) => result(intent({ assetId: asset, requestId: request, original: constraint({ version: 9 }) })));
  mount(<RoleMappingPanel />); await screen.findByRole('combobox', { name: 'Inventoried Worker / Team / CloudRole' }); await chooseActualMemberAndRole();
  fireEvent.click(consent()); fireEvent.click(screen.getByRole('button', { name: 'Adopt Role constraint manually' })); await confirm('Confirm adoption', false);
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  fireEvent.doubleClick(screen.getByRole('button', { name: 'Adopt Role constraint manually' })); fireEvent.click(originalRead());
  await screen.findByText('Original Role submission fact'); expect(read).toHaveBeenCalledTimes(1); expect(save).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('button', { name: 'Start new local action explicitly' })).toBeDisabled();
  await act(async () => pending.resolve(result(intent({ requestId: save.mock.calls[0][1].request_id, original: constraint({ version: 0 }) }))));
  await screen.findByText('Invalid Role intent receipt / 角色意图回执无法核验');
  expect(screen.getByText('9')).toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Adopt Role constraint manually' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Start new local action explicitly' })).toBeEnabled(); expect(save).toHaveBeenCalledTimes(1);
});
