import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { apigPublicationApi as api } from '@/api/apigPolicyPublication';
import { cloudApi } from '@/api/cloud';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import type { ApiResult } from '@/api/dataSource';
import type { ApigOperation } from '@/types/apigPolicyPublication';
import ApigPolicyPublicationPanel from './ApigPolicyPublicationPanel';
import { deferred, observation, operation, operationId, policyId, preview, result, state, target } from './testFixtures';
import { installHarness, mount, rights } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

async function choose() { fireEvent.click(await screen.findByRole('button', { name: 'Choose platform policy Actual projectable policy v4' })); }
async function baseline() { fireEvent.click(await screen.findByRole('button', { name: 'Explicitly adopt the latest observation as the draft baseline' })); }
async function prepare() {
  const button = screen.getByRole('button', { name: 'Prepare trusted APIG preview (no cloud write)' });
  await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button); await screen.findByText('Trusted APIG preview (no cloud write sent)');
}
async function confirm() {
  for (const name of [
    'Confirm the target, previous and desired thresholds and signed source revisions above',
    'Confirm platform Tenant minute quotas differ from the cloud API-global counting period',
    'Confirm the independent policy may be referenced by other APIs and shared impact is unknown',
    'Confirm there is no cloud CAS; the pre-write comparison cannot exclude external concurrent edits',
  ]) fireEvent.click(screen.getByRole('checkbox', { name }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Send one explicit new APIG publication' })).toBeEnabled());
}
it('prefills original UUID with GET-only entry and no private configuration or cloud observation', async () => {
  window.history.replaceState({ idx: 7, usr: { retain: true } }, '', `/alicloud?tab=apig-policy&view=guide&apig_request_id=${operationId}#help`);
  const calls = [vi.spyOn(api, 'observe'), vi.spyOn(api, 'preview'), vi.spyOn(api, 'apply'), vi.spyOn(api, 'recover'), vi.spyOn(api, 'receipt'), vi.spyOn(cloudApi, 'configuration')];
  mount(<ApigPolicyPublicationPanel />); await screen.findByText(target.sourceLabel);
  expect(screen.getByRole('textbox', { name: 'APIG publication original request UUID' })).toHaveValue(operationId);
  expect(api.state).toHaveBeenCalledWith({ source_page: 1, source_page_size: 20, source_eligible_only: false }, expect.any(AbortSignal));
  for (const call of calls) expect(call).not.toHaveBeenCalled();
});
it('requires explicit Live observation consent for a reader without permitting preview or Mock initialization', async () => {
  rights.delete('alicloud:write');
  const live = { ...target, mocked: false, transportMode: 'live' as const };
  vi.mocked(api.state).mockResolvedValue(result(state({ binding: live, observation: observation({ target: live }), canPrepare: false, canApply: false, canInitializeMockFixture: false })));
  const read = vi.spyOn(api, 'observe').mockResolvedValue(result(observation({ target: live })));
  mount(<ApigPolicyPublicationPanel />); const button = await screen.findByRole('button', { name: 'Explicitly observe the current APIG target' });
  expect(button).toBeDisabled(); fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm read-only observation of the Live target above' })); fireEvent.click(button);
  await waitFor(() => expect(read).toHaveBeenCalledTimes(1)); expect(read).toHaveBeenCalledWith(expect.objectContaining({ configuration_version: 1, confirm_live: true, initialize_mock_fixture: false }));
  expect(screen.getByRole('button', { name: 'Prepare trusted APIG preview (no cloud write)' })).toBeDisabled();
  expect(screen.queryByText('Existing five-ID binding')).not.toBeInTheDocument();
});
it('only initializes Mock after explicit consent and never depends on secure-context randomUUID', async () => {
  const secure = vi.spyOn(crypto, 'randomUUID').mockImplementation(() => { throw new Error('LAN HTTP has no randomUUID'); });
  const read = vi.spyOn(api, 'observe').mockResolvedValue(result(observation()));
  mount(<ApigPolicyPublicationPanel />); await screen.findByText(target.sourceLabel);
  expect(read).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('checkbox', { name: /Explicitly initialize the owned Mock fixture/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Explicitly observe the current APIG target' }));
  await waitFor(() => expect(read).toHaveBeenCalledWith(expect.objectContaining({ initialize_mock_fixture: true, confirm_live: false })));
  await screen.findByText(/Draft still uses state revision \/ observation: 2 \/ 40000000/); expect(secure).not.toHaveBeenCalled();
});
it('uses the exact server revision and four independent confirmations before one new publication', async () => {
  const candidate = vi.spyOn(api, 'preview').mockResolvedValue(result(preview()));
  const apply = vi.spyOn(api, 'apply').mockImplementation(async input => result(operation({ requestId: input.request_id })));
  mount(<ApigPolicyPublicationPanel />); await choose(); await baseline(); await prepare();
  expect(candidate).toHaveBeenCalledWith(expect.objectContaining({ expected_state_version: 2, observation_id: observation().id,
    change: { action: 'publish', policies: [{ policy_id: policyId, version: 4 }] } }));
  const button = screen.getByRole('button', { name: 'Send one explicit new APIG publication' }); expect(button).toBeDisabled(); expect(apply).not.toHaveBeenCalled();
  await confirm(); fireEvent.click(button); await screen.findByText('Original APIG request receipt');
  expect(apply).toHaveBeenCalledTimes(1); expect(apply.mock.calls[0][0]).toMatchObject({ preview_id: preview().id, expected_state_version: 2,
    confirm_apply: true, confirm_scope_difference: true, confirm_shared_policy_impact: true, confirm_no_cloud_cas: true, confirm_live: false, confirm_unknown_overlap: false });
  expect(button).toBeDisabled(); expect(screen.getByText('Unknown: no consumer receipt')).toBeInTheDocument();
});
it('keeps selected version and draft baseline on 409; latest GET requires explicit baseline adoption', async () => {
  const candidate = vi.spyOn(api, 'preview').mockRejectedValue(new Error('State revision conflict'));
  mount(<ApigPolicyPublicationPanel />); await choose(); await baseline();
  fireEvent.click(screen.getByRole('button', { name: 'Prepare trusted APIG preview (no cloud write)' })); await screen.findByText('State revision conflict');
  const latest = observation({ id: '40000000-0000-4000-8000-000000000099', configHash: 'new-config-hash' });
  vi.mocked(api.state).mockResolvedValue(result(state({ stateVersion: 7, observation: latest })));
  fireEvent.click(screen.getByRole('button', { name: /Refresh APIG local state to compare/ })); await screen.findByText(/new-config-hash/);
  expect(screen.getByText(/Draft still uses state revision \/ observation: 2 \/ 40000000/)).toBeInTheDocument();
  expect(screen.getByText(`Retained selected source revision: ${policyId} @ v4`)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Prepare trusted APIG preview (no cloud write)' })).toBeDisabled(); expect(candidate).toHaveBeenCalledTimes(1);
  await baseline(); fireEvent.click(screen.getByRole('button', { name: 'Prepare trusted APIG preview (no cloud write)' }));
  await waitFor(() => expect(candidate).toHaveBeenCalledTimes(2)); expect(candidate).toHaveBeenLastCalledWith(expect.objectContaining({ expected_state_version: 7, observation_id: latest.id }));
});
it('retains original UUID after a missing response and reads it without repeating the consumed preview', async () => {
  vi.spyOn(api, 'preview').mockResolvedValue(result(preview())); const apply = vi.spyOn(api, 'apply').mockRejectedValue(new Error('Response unavailable'));
  const read = vi.spyOn(api, 'receipt').mockImplementation(async id => result(operation({ requestId: id, status: 'uncertain',
    cloudWrite: { status: 'unknown', providerRequestId: null }, allowedActions: ['read_receipt'] })));
  mount(<ApigPolicyPublicationPanel />); await choose(); await baseline(); await prepare(); await confirm();
  fireEvent.click(screen.getByRole('button', { name: 'Send one explicit new APIG publication' })); await screen.findByText('Response unavailable');
  const id = apply.mock.calls[0][0].request_id; expect(screen.getByRole('textbox', { name: 'APIG publication original request UUID' })).toHaveValue(id);
  expect(screen.getByRole('button', { name: 'Send one explicit new APIG publication' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: /Read original APIG receipt \(GET only\)$/ })); await screen.findByText('Original APIG request receipt');
  expect(read).toHaveBeenCalledWith(id, expect.any(AbortSignal)); expect(apply).toHaveBeenCalledTimes(1);
  expect(screen.getByText(/Unknown or incomplete local publication is not success/)).toBeInTheDocument(); await act(async () => {});
});
it('does not display a late accepted publication or its UUID after a tenant roundtrip', async () => {
  const pending = deferred<ApiResult<ApigOperation>>(); vi.spyOn(api, 'preview').mockResolvedValue(result(preview()));
  const apply = vi.spyOn(api, 'apply').mockReturnValue(pending.promise); mount(<ApigPolicyPublicationPanel />);
  await choose(); await baseline(); await prepare(); await confirm(); fireEvent.click(screen.getByRole('button', { name: 'Send one explicit new APIG publication' }));
  await waitFor(() => expect(apply).toHaveBeenCalledTimes(1)); const id = apply.mock.calls[0][0].request_id;
  act(() => { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 });
    useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 3 }); });
  await act(async () => { pending.resolve(result(operation({ requestId: id }))); });
  expect(screen.queryByText('Original APIG request receipt')).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'APIG publication original request UUID' })).toHaveValue('');
  expect(new URLSearchParams(window.location.search).has('apig_request_id')).toBe(false); expect(apply).toHaveBeenCalledTimes(1);
});
it('lets an explicit original GET take precedence over a delayed Apply response without resending', async () => {
  const pending = deferred<ApiResult<ApigOperation>>(); vi.spyOn(api, 'preview').mockResolvedValue(result(preview()));
  const apply = vi.spyOn(api, 'apply').mockReturnValue(pending.promise), read = vi.spyOn(api, 'receipt').mockImplementation(async id => result(operation({ requestId: id,
    status: 'uncertain', cloudWrite: { status: 'unknown', providerRequestId: null }, allowedActions: ['read_receipt'] })));
  mount(<ApigPolicyPublicationPanel />); await choose(); await baseline(); await prepare(); await confirm();
  fireEvent.click(screen.getByRole('button', { name: 'Send one explicit new APIG publication' })); await waitFor(() => expect(apply).toHaveBeenCalledTimes(1));
  const id = apply.mock.calls[0][0].request_id;
  fireEvent.click(screen.getByRole('button', { name: /Read original APIG receipt \(GET only\)$/ })); await screen.findByText('unknown / —');
  await act(async () => { pending.resolve(result(operation({ requestId: id }))); });
  expect(read).toHaveBeenCalledWith(id, expect.any(AbortSignal)); expect(apply).toHaveBeenCalledTimes(1);
  expect(screen.getByText('unknown / —')).toBeInTheDocument(); expect(screen.queryByText('accepted / actual-provider-ack')).not.toBeInTheDocument();
});
