import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { cloudApi } from '@/api/cloud';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import type { ApiResult } from '@/api/dataSource';
import { publicationApi } from './api';
import MseConfigPublicationPanel from './MseConfigPublicationPanel';
import { deferred, observation, operation, operationId, policyId, preview, result, state, target } from './testFixtures';
import { installHarness, mount, rights } from './testHarness';
import type { Operation } from './types';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

async function selectPolicy() {
  const row = await screen.findByRole('row', { name: /Actual signed policy/ });
  const checkbox = within(row).getByRole('checkbox'); await waitFor(() => expect(checkbox).toBeEnabled()); fireEvent.click(checkbox);
}
async function observe() {
  fireEvent.click(await screen.findByRole('button', { name: 'Explicitly read current cloud content' }));
  await screen.findByText(/Draft still uses state revision \/ observation: 2 \/ 40000000/);
}
async function prepare() {
  const button = screen.getByRole('button', { name: /Prepare trusted preview \(no cloud write\)$/ });
  await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button);
  await screen.findByText('Trusted preview (no cloud write sent)');
}
async function confirmPublication() {
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm the target, source revisions and content hashes above' }));
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm MD5 upsert may recreate the deleted dedicated Data ID' }));
  await waitFor(() => expect(screen.getByRole('button', { name: /Send one explicit new publication$/ })).toBeEnabled());
}
it('prefills an original UUID with zero implicit business writes, cloud reads or private configuration reads', async () => {
  window.history.replaceState({ idx: 3, key: 'owned-key', usr: { view: 'retain' } }, '', `/alicloud?tab=mse-config&view=guide&publication_request_id=${operationId}#guide`);
  const observeCloud = vi.spyOn(publicationApi, 'observe'), prepareCloud = vi.spyOn(publicationApi, 'preview'), apply = vi.spyOn(publicationApi, 'apply');
  const recover = vi.spyOn(publicationApi, 'recover'), receipt = vi.spyOn(publicationApi, 'receipt'), configuration = vi.spyOn(cloudApi, 'configuration');
  const view = mount(<MseConfigPublicationPanel />); await screen.findByText('configured-source-summary');
  expect(screen.getByRole('textbox', { name: 'Configuration publication original request UUID' })).toHaveValue(operationId);
  act(() => useAuthStore.setState({ token: 'synthetic-token-refresh-with-same-scope' }));
  view.unmount(); mount(<MseConfigPublicationPanel />); await screen.findByText('configured-source-summary');
  expect(screen.getByRole('textbox', { name: 'Configuration publication original request UUID' })).toHaveValue(operationId);
  expect(new URLSearchParams(window.location.search).get('tab')).toBe('mse-config');
  expect(new URLSearchParams(window.location.search).get('view')).toBe('guide'); expect(window.location.hash).toBe('#guide');
  expect(window.history.state).toMatchObject({ idx: 3, key: 'owned-key', usr: { view: 'retain' } });
  for (const call of [observeCloud, prepareCloud, apply, recover, receipt, configuration]) expect(call).not.toHaveBeenCalled();
});
it('lets a reader observe only after explicit Live consent without granting preview or publication', async () => {
  rights.delete('alicloud:write');
  const liveTarget = { ...target, mocked: false, transportMode: 'live' as const };
  vi.mocked(publicationApi.state).mockResolvedValue(result(state({ binding: liveTarget, observation: observation({ target: liveTarget }), canPrepare: false, canApply: false })));
  const read = vi.spyOn(publicationApi, 'observe').mockResolvedValue(result(observation({ target: liveTarget })));
  mount(<MseConfigPublicationPanel />);
  const button = await screen.findByRole('button', { name: 'Explicitly read current cloud content' }); expect(button).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm a live read-only cloud observation of this target' })); fireEvent.click(button);
  await waitFor(() => expect(read).toHaveBeenCalledTimes(1));
  expect(read).toHaveBeenCalledWith(expect.objectContaining({ configuration_version: 1, confirm_live: true }));
  expect(screen.getByRole('button', { name: 'Prepare trusted preview (no cloud write)' })).toBeDisabled();
  expect(screen.queryByText('Dedicated Data ID target binding')).not.toBeInTheDocument();
});
it('requires a manual observation, exact signed revision preview and two separate confirmations before one publication', async () => {
  const secureContextOnly = vi.spyOn(crypto, 'randomUUID').mockImplementation(() => { throw new Error('randomUUID is unavailable on LAN HTTP'); });
  const read = vi.spyOn(publicationApi, 'observe').mockResolvedValue(result(observation()));
  const candidate = vi.spyOn(publicationApi, 'preview').mockResolvedValue(result(preview()));
  const apply = vi.spyOn(publicationApi, 'apply').mockImplementation(async input => result(operation({ requestId: input.request_id })));
  mount(<MseConfigPublicationPanel />); await selectPolicy(); expect(candidate).not.toHaveBeenCalled();
  await observe(); await prepare();
  expect(candidate).toHaveBeenCalledWith(expect.objectContaining({ configuration_version: 1, observation_id: observation().id, expected_state_version: 2,
    change: { action: 'publish', policies: [{ policy_id: policyId, version: 4 }] } }));
  const button = screen.getByRole('button', { name: /Send one explicit new publication$/ }); expect(button).toBeDisabled(); expect(apply).not.toHaveBeenCalled();
  await confirmPublication(); fireEvent.click(button);
  await waitFor(() => expect(apply).toHaveBeenCalledTimes(1)); await screen.findByText('Original request receipt');
  const input = apply.mock.calls[0][0];
  expect(input).toMatchObject({ preview_id: preview().id, expected_state_version: 2, confirm_apply: true, confirm_upsert: true, confirm_live: false, confirm_unknown_overlap: false });
  expect(input.request_id).not.toBe(read.mock.calls[0][0].request_id); expect(button).toBeDisabled();
  expect(secureContextOnly).not.toHaveBeenCalled();
  expect(screen.getByText('Unknown: no consumer receipt')).toBeInTheDocument();
});
it('preserves the selected policy and original baseline after 409 and an independent latest-state GET', async () => {
  vi.spyOn(publicationApi, 'observe').mockResolvedValue(result(observation()));
  const candidate = vi.spyOn(publicationApi, 'preview').mockRejectedValue(new Error('Policy or state revision conflict'));
  mount(<MseConfigPublicationPanel />); await selectPolicy(); await observe();
  const first = screen.getByRole('button', { name: /Prepare trusted preview \(no cloud write\)$/ });
  await waitFor(() => expect(first).toBeEnabled()); fireEvent.click(first); await screen.findByText('Policy or state revision conflict');
  vi.mocked(publicationApi.state).mockResolvedValue(result(state({ stateVersion: 7, observation: observation({ id: '40000000-0000-4000-8000-000000000099', contentHash: 'latest-cloud-hash' }) })));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh local state to compare (GET only)' })); await screen.findByText('latest-cloud-hash');
  expect(screen.getByText(/Draft still uses state revision \/ observation: 2 \/ 40000000/)).toBeInTheDocument();
  expect(within(screen.getByRole('row', { name: /Actual signed policy/ })).getByRole('checkbox')).toBeChecked(); expect(candidate).toHaveBeenCalledTimes(1);
  const again = screen.getByRole('button', { name: /Prepare trusted preview \(no cloud write\)$/ });
  await waitFor(() => expect(again).toBeEnabled()); fireEvent.click(again);
  await waitFor(() => expect(candidate).toHaveBeenCalledTimes(2));
  expect(candidate).toHaveBeenLastCalledWith(expect.objectContaining({ expected_state_version: 2, observation_id: observation().id, change: { action: 'publish', policies: [{ policy_id: policyId, version: 4 }] } }));
});
it('retains the attempted UUID after a lost response and never resends its consumed preview', async () => {
  vi.spyOn(publicationApi, 'observe').mockResolvedValue(result(observation())); vi.spyOn(publicationApi, 'preview').mockResolvedValue(result(preview()));
  const apply = vi.spyOn(publicationApi, 'apply').mockRejectedValue(new Error('Response unavailable'));
  const receipt = vi.spyOn(publicationApi, 'receipt').mockImplementation(async id => result(operation({ requestId: id, status: 'uncertain',
    cloudWrite: { status: 'unknown' }, localPublication: { status: 'not_staged' }, allowedActions: ['read_receipt'] })));
  mount(<MseConfigPublicationPanel />); await selectPolicy(); await observe(); await prepare(); await confirmPublication();
  fireEvent.click(screen.getByRole('button', { name: /Send one explicit new publication$/ })); await screen.findByText('Response unavailable');
  const id = apply.mock.calls[0][0].request_id;
  expect(screen.getByRole('textbox', { name: 'Configuration publication original request UUID' })).toHaveValue(id);
  expect(screen.getByRole('button', { name: /Send one explicit new publication$/ })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Read original publication receipt (GET only)' })); await screen.findByText('Original request receipt');
  expect(receipt).toHaveBeenCalledWith(id); expect(apply).toHaveBeenCalledTimes(1);
  expect(screen.getByText(/This cloud write has an unknown outcome/)).toBeInTheDocument();
});
it.each(['tenant', 'session', 'tenant-roundtrip'])('clears the URL and drops a late original receipt across a %s change', async change => {
  window.history.replaceState({ idx: 3, key: 'owned-key', usr: { view: 'retain' } }, '', '/alicloud?tab=mse-config&view=guide#guide');
  const pending = deferred<ApiResult<Operation>>();
  const receipt = vi.spyOn(publicationApi, 'receipt').mockReturnValue(pending.promise);
  mount(<MseConfigPublicationPanel />); await screen.findByText('configured-source-summary');
  fireEvent.change(screen.getByRole('textbox', { name: 'Configuration publication original request UUID' }), { target: { value: operationId } });
  fireEvent.click(screen.getByRole('button', { name: 'Read original publication receipt (GET only)' })); await waitFor(() => expect(receipt).toHaveBeenCalledTimes(1));
  vi.mocked(publicationApi.state).mockResolvedValue(result(state({ binding: { ...target, sourceLabel: 'new-tenant-source' } })));
  act(() => {
    if (change === 'session') useAuthStore.setState({ sessionGeneration: 2 });
    else {
      useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 });
      if (change === 'tenant-roundtrip') useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 3 });
    }
  });
  await screen.findByText('new-tenant-source'); await act(async () => { pending.resolve(result(operation())); });
  expect(screen.queryByText('Original request receipt')).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Configuration publication original request UUID' })).toHaveValue('');
  expect(new URLSearchParams(window.location.search).has('publication_request_id')).toBe(false);
  expect(new URLSearchParams(window.location.search).get('tab')).toBe('mse-config');
  expect(new URLSearchParams(window.location.search).get('view')).toBe('guide'); expect(window.location.hash).toBe('#guide');
  expect(window.history.state).toMatchObject({ idx: 3, key: 'owned-key', usr: { view: 'retain' } });
  expect(receipt).toHaveBeenCalledTimes(1);
});
