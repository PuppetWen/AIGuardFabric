import { fireEvent, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { agentteamsRoleMappingApi as api } from '@/api/agentteamsRoleMapping';
import { ApiRequestError } from '@/api/transport';
import RoleMappingPanel from './RoleMappingPanel';
import { assetId, constraint, intent, result, roleId, state } from './testFixtures';
import { installHarness, mount, rights } from './testHarness';
import { choose, chooseActualMemberAndRole, confirm, consent } from './testInteractions';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('loads real catalog without business writes or a default Role, then sends one explicitly confirmed local constraint', async () => {
  const save = vi.spyOn(api, 'save').mockImplementation(async (asset, body) => result(intent({ assetId: asset, requestId: body.request_id, original: constraint({ version: 1, currentQualified: null }) })));
  const read = vi.spyOn(api, 'receipt'); mount(<RoleMappingPanel />);
  await screen.findByRole('combobox', { name: 'Inventoried Worker / Team / CloudRole' });
  expect(screen.queryByRole('combobox', { name: 'Actual platform Role UUID' })).not.toBeInTheDocument();
  expect(save).not.toHaveBeenCalled(); expect(read).not.toHaveBeenCalled();
  await chooseActualMemberAndRole(); expect(consent()).not.toBeChecked();
  const adopt = screen.getByRole('button', { name: 'Adopt Role constraint manually' }); expect(adopt).toBeDisabled();
  fireEvent.click(consent()); fireEvent.click(adopt); expect(save).not.toHaveBeenCalled();
  await confirm('Confirm adoption'); await screen.findByText('Original Role submission fact');
  expect(save).toHaveBeenCalledTimes(1);
  expect(save).toHaveBeenCalledWith(assetId, expect.objectContaining({ request_id: expect.stringMatching(/^[0-9a-f-]{36}$/),
    expected_version: 0, confirm_local_constraint: true, change: expect.objectContaining({ action: 'adopt', configuration_version: 1,
      worker_name: 'Actual Worker', team_name: 'Actual Team', cloud_role: 'Actual CloudRole', role_id: roleId }) }), expect.any(AbortSignal));
  expect(consent()).not.toBeChecked(); expect(read).not.toHaveBeenCalled();
  expect(screen.getByRole('textbox', { name: 'Original Role request UUID' })).toHaveValue(save.mock.calls[0][1].request_id);
});

it('retains draft and expected version after conflict; GET comparison does not adopt or write and explicit adoption needs a new confirmation', async () => {
  vi.mocked(api.state).mockResolvedValueOnce(result(state({ items: [constraint()], mappedCount: 1 })))
    .mockResolvedValue(result(state({ items: [constraint({ version: 7 })], mappedCount: 1 })));
  const save = vi.spyOn(api, 'save').mockRejectedValueOnce(new ApiRequestError('Current constraint CAS conflict', 409, 'conflict', false))
    .mockImplementation(async (asset, body) => result(intent({ assetId: asset, requestId: body.request_id, original: constraint({ version: 8 }) })));
  mount(<RoleMappingPanel />); await screen.findByRole('combobox', { name: 'Inventoried Worker / Team / CloudRole' }); await chooseActualMemberAndRole();
  fireEvent.click(consent()); fireEvent.click(screen.getByRole('button', { name: 'Adopt Role constraint manually' })); await confirm('Confirm adoption');
  await screen.findByText('Current constraint CAS conflict'); expect(save.mock.calls[0][1].expected_version).toBe(3);
  const firstId = save.mock.calls[0][1].request_id;
  fireEvent.click(screen.getByRole('button', { name: /Reload Roles and members to compare/ }));
  await screen.findByText(/Draft save version \/ current mapping version: 3 \/ 7/); expect(save).toHaveBeenCalledTimes(1); expect(consent()).toBeChecked();
  expect(screen.getByRole('textbox', { name: 'Original Role request UUID' })).toHaveValue(firstId);
  fireEvent.click(screen.getByRole('button', { name: 'Start new local action explicitly' })); await confirm('Confirm new local action');
  fireEvent.click(screen.getByRole('button', { name: 'Adopt latest comparison explicitly (no save)' })); await confirm('Confirm latest adoption');
  expect(screen.getByText(/Draft save version \/ current mapping version: 7 \/ 7/)).toBeInTheDocument(); expect(consent()).not.toBeChecked(); expect(save).toHaveBeenCalledTimes(1);
  fireEvent.click(consent()); fireEvent.click(screen.getByRole('button', { name: 'Adopt Role constraint manually' })); await confirm('Confirm adoption');
  expect(save).toHaveBeenCalledTimes(2); expect(save.mock.calls[1][1].expected_version).toBe(7); expect(save.mock.calls[1][1].request_id).not.toBe(firstId);
});

it('requires an explicit disable confirmation and the reviewed version, with no delete-to-restore action', async () => {
  vi.mocked(api.state).mockResolvedValue(result(state({ items: [constraint()], mappedCount: 1 })));
  const save = vi.spyOn(api, 'save').mockImplementation(async (asset, body) => result(intent({ assetId: asset, requestId: body.request_id,
    original: constraint({ version: 4, eligibility: 'disabled', currentQualified: null }) })));
  mount(<RoleMappingPanel />); fireEvent.click(await screen.findByRole('button', { name: 'Disable Actual Worker' }));
  expect(save).not.toHaveBeenCalled(); await screen.findByText(/Disable retains the permanent governed identity/); await confirm('Confirm disable');
  expect(save).toHaveBeenCalledWith(assetId, expect.objectContaining({ expected_version: 3, confirm_local_constraint: true,
    change: { action: 'disable' } }), expect.any(AbortSignal));
  expect(screen.queryByRole('button', { name: /Delete|Unlock/ })).not.toBeInTheDocument();
});

it('retains an unavailable old Role UUID for repair without validating it or choosing a substitute', async () => {
  const missing = '10000000-0000-7000-8000-000000000099', current = constraint();
  vi.mocked(api.state).mockResolvedValue(result(state({ items: [{ ...current, proof: { ...current.proof, platformRoleId: missing } }], mappedCount: 0 })));
  const save = vi.spyOn(api, 'save'); mount(<RoleMappingPanel />);
  await screen.findByRole('combobox', { name: 'Inventoried Worker / Team / CloudRole' });
  await choose('Inventoried Worker / Team / CloudRole', 'Actual Worker / Actual Team / Actual CloudRole');
  expect(screen.getByText(`Retained Role UUID unavailable in current catalog: ${missing}`)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Adopt Role constraint manually' })).toBeDisabled(); expect(save).not.toHaveBeenCalled();
});

it('does not fabricate a catalog or write on query failure; offline mode explicitly leaves unmanaged Keys compatible', async () => {
  vi.mocked(api.state).mockRejectedValueOnce(new Error('Role catalog unavailable'))
    .mockResolvedValue(result(state({ catalogAvailable: false, canManage: false, roles: [], workers: [] })));
  const save = vi.spyOn(api, 'save'); mount(<RoleMappingPanel />); await screen.findByText('Role catalog unavailable');
  expect(screen.queryByRole('combobox')).not.toBeInTheDocument(); expect(save).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: /Reload Roles and members/ })); await screen.findByText(/Offline mode has no actual Role UUID catalog/);
  expect(screen.queryByRole('combobox')).not.toBeInTheDocument(); expect(save).not.toHaveBeenCalled();
});

it('separates read-only catalog access from adoption/disable permissions', async () => {
  rights.delete('assets:write'); vi.mocked(api.state).mockResolvedValue(result(state({ canManage: false, items: [constraint()] })));
  const save = vi.spyOn(api, 'save'); mount(<RoleMappingPanel />);
  expect(await screen.findByRole('button', { name: 'Disable Actual Worker' })).toBeDisabled();
  expect(screen.getByRole('combobox', { name: 'Inventoried Worker / Team / CloudRole' })).toBeDisabled(); expect(save).not.toHaveBeenCalled();
});

it('a missing read grant makes no catalog request and offers no write', async () => {
  rights.delete('platform:admin'); mount(<RoleMappingPanel />); await screen.findByText('Reading requires platform:admin + alicloud:read');
  expect(api.state).not.toHaveBeenCalled();
});

it('displays old committed qualification beyond 300 seconds without treating it as a runtime expiry or auto-adopting', async () => {
  const row = constraint(); row.proof.observedAt = new Date(Date.now() - 3_600_000).toISOString();
  vi.mocked(api.state).mockResolvedValue(result(state({ items: [row], mappedCount: 1 })));
  const save = vi.spyOn(api, 'save'); mount(<RoleMappingPanel />);
  await screen.findByText('Currently qualified mappings: 1'); expect(screen.getByText('Current qualification: eligible')).toBeInTheDocument();
  expect(save).not.toHaveBeenCalled();
});
