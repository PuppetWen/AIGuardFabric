import { fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { apigConfigurationApi as api } from '@/api/apigConfigurationPublication';
import { cloudApi } from '@/api/cloud';
import ApigConfigurationPublicationPanel from './ApigConfigurationPublicationPanel';
import { observation, operation, operationId, preview, result, state, target } from './testFixtures';
import { installHarness, mount, rights } from './testHarness';
import { adopt, confirm, prepare } from './testActions';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('prefills a deep link without private configuration, automatic observation, initialization or receipt reads', async () => {
  window.history.replaceState({ idx: 7, usr: { retain: true } }, '', `/alicloud?tab=apig-config&keep=user-view&apig_configuration_request_id=${operationId}#help`);
  const calls = [vi.spyOn(api, 'observe'), vi.spyOn(api, 'preview'), vi.spyOn(api, 'apply'), vi.spyOn(api, 'recover'), vi.spyOn(api, 'receipt'), vi.spyOn(cloudApi, 'configuration')];
  mount(<ApigConfigurationPublicationPanel />); await screen.findByText(target.sourceLabel);
  expect(screen.getByRole('textbox', { name: 'APIG configuration original request UUID' })).toHaveValue(operationId);
  expect(api.state).toHaveBeenCalledWith(expect.any(AbortSignal)); for (const call of calls) expect(call).not.toHaveBeenCalled();
});
it('a reader must confirm Live observation and cannot initialize Mock or load secret configuration', async () => {
  rights.delete('alicloud:write');
  const live = { ...target, mocked: false, transportMode: 'live' as const };
  vi.mocked(api.state).mockResolvedValue(result(state({ binding: live, observation: observation({ target: live }), canInitializeMockFixture: false, canApply: false, canPrepare: false })));
  const observed = vi.spyOn(api, 'observe').mockResolvedValue(result(observation({ target: live }))), configuration = vi.spyOn(cloudApi, 'configuration');
  mount(<ApigConfigurationPublicationPanel />); const button = await screen.findByRole('button', { name: 'Explicitly observe the APIG configuration target' });
  expect(button).toBeDisabled(); fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm read-only observation of the Live target above' })); fireEvent.click(button);
  await waitFor(() => expect(observed).toHaveBeenCalledWith(expect.objectContaining({ confirm_live: true, initialize_mock_fixture: false })));
  expect(screen.queryByText('Existing configuration target binding')).not.toBeInTheDocument(); expect(configuration).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Prepare APIG configuration preview' })).toBeDisabled();
});
it('initializes Mock only with explicit consent, and observation never silently adopts the baseline', async () => {
  const secure = vi.spyOn(crypto, 'randomUUID').mockImplementation(() => { throw new Error('No secure-context UUID'); });
  const observed = vi.spyOn(api, 'observe').mockResolvedValue(result(observation()));
  mount(<ApigConfigurationPublicationPanel />); await screen.findByText(target.sourceLabel);
  expect(observed).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('checkbox', { name: /Explicitly initialize the owned Mock example/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Explicitly observe the APIG configuration target' }));
  await waitFor(() => expect(observed).toHaveBeenCalledWith(expect.objectContaining({ configuration_version: 1, confirm_live: false, initialize_mock_fixture: true })));
  expect(screen.getByText('Draft still uses observation: —')).toBeInTheDocument(); expect(secure).not.toHaveBeenCalled();
});
it('sends the edited public settings with the adopted revision and requires four separate confirmations', async () => {
  const prepared = vi.spyOn(api, 'preview').mockResolvedValue(result(preview()));
  const applied = vi.spyOn(api, 'apply').mockImplementation(async body => result(operation({ requestId: body.request_id })));
  mount(<ApigConfigurationPublicationPanel />); await adopt(); fireEvent.click(screen.getByRole('checkbox', { name: 'checkResponse' })); await prepare();
  expect(prepared).toHaveBeenCalledWith(expect.objectContaining({ configuration_version: 1, observation_id: observation().id, expected_state_version: 2,
    change: { action: 'content', settings: { enabled: true, checkRequest: true, checkResponse: true, denyCode: 403 } } }));
  const button = screen.getByRole('button', { name: 'Send one explicit new APIG configuration write' }); expect(button).toBeDisabled(); await confirm();
  fireEvent.click(button); fireEvent.click(button); await screen.findByText('Original APIG configuration request receipt');
  expect(applied).toHaveBeenCalledTimes(1); expect(applied.mock.calls[0][0]).toMatchObject({ preview_id: preview().id, expected_state_version: 2,
    confirm_apply: true, confirm_preserved_private_configuration: true, confirm_streaming_or_shared_impact: true, confirm_no_cloud_cas: true, confirm_live: false });
  expect(button).toBeDisabled(); expect(screen.getByText('Unknown; verify the actual workload independently')).toBeInTheDocument();
});
it('keeps edited content and old baseline on conflict and a newer GET until explicit adoption', async () => {
  const prepared = vi.spyOn(api, 'preview').mockRejectedValue(new Error('Preview revision conflict'));
  mount(<ApigConfigurationPublicationPanel />); await adopt(); fireEvent.click(screen.getByRole('checkbox', { name: 'checkResponse' }));
  fireEvent.click(screen.getByRole('button', { name: 'Prepare APIG configuration preview' })); await screen.findByText('Preview revision conflict');
  const latest = observation({ id: '40000000-0000-4000-8000-000000000099', contentHash: 'new-config-hash' });
  vi.mocked(api.state).mockResolvedValue(result(state({ stateVersion: 7, observation: latest })));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh APIG configuration local state (GET only)' })); await screen.findByText(/new-config-hash/);
  expect(screen.getByRole('checkbox', { name: 'checkResponse' })).toBeChecked();
  expect(screen.getByText(`Draft still uses observation: ${observation().id}`)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Prepare APIG configuration preview' })).toBeDisabled(); expect(prepared).toHaveBeenCalledTimes(1);
  await adopt(); expect(screen.getByRole('checkbox', { name: 'checkResponse' })).not.toBeChecked();
  fireEvent.click(screen.getByRole('button', { name: 'Prepare APIG configuration preview' }));
  await waitFor(() => expect(prepared).toHaveBeenCalledTimes(2)); expect(prepared).toHaveBeenLastCalledWith(expect.objectContaining({ expected_state_version: 7, observation_id: latest.id }));
});
it('uses actual model slots, retains their identity and rejects an invalid total without dispatch', async () => {
  const modelTarget = { ...target, binding: { kind: 'models' as const, binding: { httpApiId: 'api-owned', gatewayId: 'gw-owned', environmentId: 'env-owned' } } };
  const observed = observation({ target: modelTarget, view: { services: [
    { serviceId: 'svc-a', version: 'v1', modelName: 'model-a', weight: 60 }, { serviceId: 'svc-b', version: null, modelName: 'model-b', weight: 40 } ], backendScene: 'MultiServiceByRatio' } });
  vi.mocked(api.state).mockResolvedValue(result(state({ binding: modelTarget, observation: observed })));
  const prepared = vi.spyOn(api, 'preview').mockResolvedValue(result(preview({ target: modelTarget })));
  mount(<ApigConfigurationPublicationPanel />); await adopt();
  fireEvent.change(screen.getByRole('spinbutton', { name: 'Service weight 1' }), { target: { value: '50' } });
  expect(screen.getByRole('button', { name: 'Prepare APIG configuration preview' })).toBeDisabled(); expect(prepared).not.toHaveBeenCalled();
  fireEvent.change(screen.getByRole('spinbutton', { name: 'Service weight 2' }), { target: { value: '50' } }); await prepare();
  expect(prepared).toHaveBeenCalledWith(expect.objectContaining({ change: { action: 'models', services: [
    { serviceId: 'svc-a', version: 'v1', modelName: 'model-a', expectedModelName: 'model-a', weight: 50 },
    { serviceId: 'svc-b', version: null, modelName: 'model-b', expectedModelName: 'model-b', weight: 50 } ] } }));
});
