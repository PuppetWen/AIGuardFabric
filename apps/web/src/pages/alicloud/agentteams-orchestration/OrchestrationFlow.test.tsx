import { fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { ApiRequestError } from '@/api/transport';
import { agentteamsOrchestrationApi as api } from '@/api/agentteamsOrchestration';
import OrchestrationPanel from './OrchestrationPanel';
import { definition, receipt, record, result, state, target } from './testFixtures';
import { installHarness, mount, rights } from './testHarness';
import { apply, confirm, confirmOwnership, editor, prepare, selectTeam } from './testInteractions';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('starts with GET only; editing/importing, consent and preview do not commit; the reviewed body is submitted once', async () => {
  vi.mocked(api.apply).mockImplementation(async (_team, body) => result(receipt(body)));
  mount(<OrchestrationPanel />); await selectTeam();
  expect(api.preview).not.toHaveBeenCalled(); expect(api.apply).not.toHaveBeenCalled(); expect(api.receipt).not.toHaveBeenCalled();
  const candidate = definition(); candidate.nodes[0].name = 'Reviewed candidate';
  fireEvent.change(editor(), { target: { value: JSON.stringify(candidate) } });
  await prepare(); expect(api.apply).not.toHaveBeenCalled();
  const body = vi.mocked(api.preview).mock.calls[0][1];
  expect(body.expected_version).toBe(3); expect(body.change).toEqual({ action: 'save_definition', definition: candidate });
  expect(screen.getByRole('button', { name: 'Commit the reviewed candidate' })).toBeEnabled();
  await apply(); await screen.findByText('Immutable original receipt');
  expect(api.apply).toHaveBeenCalledTimes(1); expect(vi.mocked(api.apply).mock.calls[0][1]).toBe(body);
  expect(Object.isFrozen(body)).toBe(true); expect(Object.isFrozen(body.change)).toBe(true);
  if (body.change.action === 'save_definition') expect(Object.isFrozen(body.change.definition.nodes[0].agent_ids)).toBe(true);
  expect(screen.getByText(/Draft baseline revision: 4/)).toBeInTheDocument(); expect(confirmOwnership()).not.toBeChecked();
});

it('adds an explicitly selected real Worker via the node form without writing or choosing an arbitrary Worker', async () => {
  mount(<OrchestrationPanel />); await selectTeam();
  fireEvent.change(screen.getByRole('textbox', { name: 'New node ID' }), { target: { value: 'child' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'New node name' }), { target: { value: 'Application child' } });
  fireEvent.click(screen.getByRole('button', { name: 'Add a node to the draft only' }));
  await screen.findByText('Provide a unique node and observed Workers; cron must be explicit.');
  expect(JSON.parse((editor() as HTMLTextAreaElement).value).nodes).toHaveLength(1);
  fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Assign observed Workers' }));
  fireEvent.click(await screen.findByText('Actual Worker', { selector: '.ant-select-item-option-content' }));
  fireEvent.click(screen.getByRole('button', { name: 'Add a node to the draft only' }));
  expect(JSON.parse((editor() as HTMLTextAreaElement).value).nodes[1]).toMatchObject({ node_id: 'child', agent_ids: ['Actual Worker'], trigger: 'manual' });
  expect(api.preview).not.toHaveBeenCalled(); expect(api.apply).not.toHaveBeenCalled();
});

it('rejects unsupported import fields before POST and retains the exact invalid draft', async () => {
  mount(<OrchestrationPanel />); await selectTeam();
  const text = JSON.stringify({ ...definition(), handler_code: 'unsupported' });
  fireEvent.change(editor(), { target: { value: text } }); fireEvent.click(confirmOwnership());
  fireEvent.click(screen.getByRole('button', { name: 'Validate DAG and preview differences (no save)' }));
  await screen.findByText('Invalid declaration fields / 声明字段无效');
  expect(editor()).toHaveValue(text); expect(api.preview).not.toHaveBeenCalled(); expect(api.apply).not.toHaveBeenCalled();
});

it('keeps a 409 draft and CAS through GET comparison, then only an explicit adoption uses the latest baseline', async () => {
  vi.mocked(api.apply).mockRejectedValueOnce(new ApiRequestError('Version conflict', 409, 'conflict', false))
    .mockImplementation(async (_team, body) => result(receipt(body)));
  vi.mocked(api.state).mockResolvedValueOnce(result(state())).mockResolvedValue(result(state({ teams: [target({ current: record({ version: 7 }) })] })));
  mount(<OrchestrationPanel />); await selectTeam();
  const text = JSON.stringify({ ...definition(), nodes: [{ ...definition().nodes[0], name: 'Preserved draft' }] });
  fireEvent.change(editor(), { target: { value: text } }); await prepare(); await apply(); await screen.findByText('Version conflict');
  fireEvent.click(screen.getByRole('button', { name: /Reload current state to compare/ })); await screen.findByText('Latest read revision: 7');
  expect(editor()).toHaveValue(text); expect(vi.mocked(api.apply).mock.calls[0][1].expected_version).toBe(3);
  expect(screen.getByRole('button', { name: 'Adopt the read baseline explicitly (no save)' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Start a new action explicitly (keep draft baseline)' }));
  fireEvent.click(screen.getByRole('button', { name: 'Adopt the read baseline explicitly (no save)' })); await confirm('Adopt explicitly');
  expect(api.apply).toHaveBeenCalledTimes(1); expect(JSON.parse((editor() as HTMLTextAreaElement).value).nodes[0].name).toBe('Preserved draft');
  await prepare(); await apply();
  expect(api.apply).toHaveBeenCalledTimes(2); expect(vi.mocked(api.apply).mock.calls[1][1].expected_version).toBe(7);
  expect(vi.mocked(api.apply).mock.calls[1][1].request_id).not.toBe(vi.mocked(api.apply).mock.calls[0][1].request_id);
});

it('keeps Mock receiver sync separate and requires its explicit confirmation before committing', async () => {
  vi.mocked(api.apply).mockImplementation(async (_team, body) => result(receipt(body)));
  mount(<OrchestrationPanel />); await selectTeam();
  fireEvent.click(screen.getByRole('radio', { name: 'Sync the Mock receiver' })); await prepare();
  expect(screen.getByRole('button', { name: 'Commit the reviewed candidate' })).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox', { name: /Confirm syncing only the application-owned Mock receiver/ }));
  await prepare(); await apply();
  expect(vi.mocked(api.apply).mock.calls[0][1]).toMatchObject({ change: { action: 'sync', direction: 'push' }, confirm_mock_sync: true });
  expect(screen.getByText('Not called')).toBeInTheDocument(); expect(api.apply).toHaveBeenCalledTimes(1);
});

it('read-only permissions allow original GETs but cannot preview or commit', async () => {
  rights.delete('platform:admin'); rights.delete('alicloud:write'); vi.mocked(api.receipt).mockResolvedValue(result(receipt()));
  mount(<OrchestrationPanel />); const select = await screen.findByRole('combobox', { name: 'Observed Team' });
  expect(select).toBeDisabled();
  fireEvent.change(screen.getByRole('textbox', { name: 'Original orchestration request UUID' }), { target: { value: receipt().requestId } });
  fireEvent.click(screen.getByRole('button', { name: /Read the original receipt/ })); await screen.findByText('Immutable original receipt');
  expect(api.receipt).toHaveBeenCalledTimes(1); expect(api.preview).not.toHaveBeenCalled(); expect(api.apply).not.toHaveBeenCalled();
});

it('a failed GET provides no example inventory, default Team or fabricated declaration', async () => {
  vi.mocked(api.state).mockRejectedValue(new ApiRequestError('Actual source unavailable', 503, 'dependency', false));
  mount(<OrchestrationPanel />); await screen.findByText('Actual source unavailable');
  expect(screen.queryByRole('combobox', { name: 'Observed Team' })).not.toBeInTheDocument();
  expect(screen.queryByRole('textbox', { name: 'DAG declaration JSON' })).not.toBeInTheDocument();
  expect(api.preview).not.toHaveBeenCalled(); expect(api.apply).not.toHaveBeenCalled();
});

it('source adoption keeps nodes but needs explicit source-change consent and never silently saves', async () => {
  vi.mocked(api.state).mockResolvedValueOnce(result(state())).mockResolvedValue(result(state({ teams: [target({ source: { ...record().source, configurationVersion: 2, inventoryFingerprint: 'd'.repeat(64) } })] })));
  mount(<OrchestrationPanel />); await selectTeam();
  fireEvent.click(screen.getByRole('button', { name: /Reload current state to compare/ }));
  await waitFor(() => expect(screen.getByText(/The current revision or source changed/)).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Adopt the read baseline explicitly (no save)' })); await confirm('Adopt explicitly');
  expect(JSON.parse((editor() as HTMLTextAreaElement).value)).toMatchObject({ inventory_fingerprint: 'd'.repeat(64), nodes: definition().nodes });
  expect(screen.getByRole('checkbox', { name: /If the source changed/ })).not.toBeChecked(); expect(api.apply).not.toHaveBeenCalled();
});
