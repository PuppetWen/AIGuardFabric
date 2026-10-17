import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { apigPublicationApi as api } from '@/api/apigPolicyPublication';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import ApigPolicyPublicationPanel from './ApigPolicyPublicationPanel';
import ApigReceipt from './ApigReceipt';
import ApigCandidate from './ApigCandidate';
import ApigPreview from './ApigPreview';
import { deferred, observation, operation, operationId, policyId, preview, result, state, target } from './testFixtures';
import { installHarness, mount } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();
const clipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
afterEach(() => { if (clipboard) Object.defineProperty(navigator, 'clipboard', clipboard); else Reflect.deleteProperty(navigator, 'clipboard'); });
async function readOriginal() {
  await waitFor(() => expect(screen.getByRole('button', { name: /Refresh APIG local state to compare/ })).not.toHaveClass('ant-btn-loading'));
  const input = screen.getByRole('textbox', { name: 'APIG publication original request UUID' });
  fireEvent.change(input, { target: { value: operationId } }); expect(input).toHaveValue(operationId);
  const read = screen.getByRole('button', { name: /Read original APIG receipt \(GET only\)$/ }); expect(read).toBeEnabled(); fireEvent.click(read);
  await waitFor(() => expect(api.receipt).toHaveBeenCalledWith(operationId, expect.any(AbortSignal)));
  await screen.findByText('Original APIG request receipt');
}
async function confirmRecovery() {
  fireEvent.click(screen.getByRole('button', { name: 'Explicitly recover the local APIG receipt' }));
  const button = await screen.findByRole('button', { name: 'Confirm local-only recovery' });
  await waitFor(() => { expect(button).toBeVisible(); expect(button).toBeEnabled(); }); fireEvent.click(button);
}
it('recovers pending local audit after configuration is disabled without dispatch, and preserves pending evidence on failure', async () => {
  vi.mocked(api.state).mockResolvedValue(result(state({ enabled: false, binding: null, canObserve: false, canPrepare: false, canApply: false })));
  const pending = operation({ status: 'uncertain', completionState: 'pending_audit', finishedAt: null, localPublication: { status: 'pending_audit' },
    sourceCurrent: false, recoveryScopeId: null, recoveryConfigurationVersion: null, allowedActions: ['read_receipt', 'recover_local'] });
  vi.spyOn(api, 'receipt').mockResolvedValue(result(pending));
  const recover = vi.spyOn(api, 'recover').mockRejectedValueOnce(new Error('Local audit commit unavailable')).mockResolvedValue(result(operation({ sourceCurrent: false })));
  const apply = vi.spyOn(api, 'apply'), observe = vi.spyOn(api, 'observeOriginal');
  mount(<ApigPolicyPublicationPanel />); await readOriginal(); await confirmRecovery(); await screen.findByText('Local audit commit unavailable');
  expect(screen.getByText('pending_audit / pending_audit')).toBeInTheDocument();
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Confirm local-only recovery' })).not.toBeInTheDocument());
  await waitFor(() => expect(screen.getByRole('button', { name: 'Explicitly recover the local APIG receipt' })).toBeEnabled());
  await confirmRecovery(); await screen.findByText('published / complete');
  expect(recover).toHaveBeenNthCalledWith(1, operationId); expect(recover).toHaveBeenNthCalledWith(2, operationId);
  expect(screen.getByText(/Actual configured APIG source \/ v1/)).toBeInTheDocument();
  expect(screen.getByText('Unknown: no consumer receipt')).toBeInTheDocument(); expect(apply).not.toHaveBeenCalled(); expect(observe).not.toHaveBeenCalled();
});
it('uses server-approved recovery configuration for a separate observation and never upgrades Unknown to success', async () => {
  const current = { ...target, configurationVersion: 2 }, fresh = observation({ target: current });
  vi.mocked(api.state).mockResolvedValue(result(state({ binding: current, observation: fresh })));
  const original = operation({ status: 'uncertain', cloudWrite: { status: 'unknown', providerRequestId: null }, recoveryConfigurationVersion: 2,
    allowedActions: ['read_receipt', 'observe'] });
  const read = vi.spyOn(api, 'receipt').mockResolvedValue(result(original)), observe = vi.spyOn(api, 'observeOriginal').mockResolvedValue(result(fresh));
  const apply = vi.spyOn(api, 'apply'); mount(<ApigPolicyPublicationPanel />); await readOriginal();
  fireEvent.click(screen.getByRole('button', { name: 'Explicitly observe the original target separately (original write outcome is retained)' }));
  await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
  expect(observe).toHaveBeenCalledWith(operationId, expect.objectContaining({ configuration_version: 2, confirm_live: false }));
  expect(observe.mock.calls[0][1]).not.toHaveProperty('initialize_mock_fixture');
  expect(screen.getByText('unknown / —')).toBeInTheDocument(); expect(screen.getByText(/Unknown or incomplete local publication is not success/)).toBeInTheDocument();
  expect(screen.getByText(/Actual configured APIG source \/ v1/)).toBeInTheDocument(); expect(apply).not.toHaveBeenCalled();
});
it('requires local completion, post-lease observation times and an exact old-ID acknowledgment before an independent new intent', async () => {
  const lease = new Date(Date.now() - 30000).toISOString(), at = new Date(Date.now() - 1000).toISOString();
  const old = operation({ status: 'uncertain', leaseExpiresAt: lease }), data = state({ unresolvedOperationId: operationId, operations: [old] });
  const prepare = vi.fn(), props = { data, operation: old, selected: { policyId, version: 4 }, onSelect: vi.fn(), rollbackId: null,
    onPublishMode: vi.fn(), canWrite: true, busy: false, loading: false, eligibleOnly: false, onSourcePage: vi.fn(), onPrepare: prepare, onRead: vi.fn() };
  const view = mount(<ApigCandidate {...props} baseline={{ stateVersion: 2, observation: observation({ startedAt: lease, observedAt: at }) }} />);
  const ack = screen.getByRole('checkbox', { name: `Acknowledge old Unknown ID ${operationId} for this new intent` }); expect(ack).toBeDisabled();
  view.rerender(<ApigCandidate {...props} baseline={{ stateVersion: 2, observation: observation({ startedAt: at, observedAt: at }) }} />);
  expect(ack).toBeEnabled(); fireEvent.click(ack); fireEvent.click(screen.getByRole('button', { name: 'Prepare trusted APIG preview (no cloud write)' }));
  expect(prepare).toHaveBeenCalledWith({ action: 'publish', policies: [{ policy_id: policyId, version: 4 }] }, true);
});
it('requires separate Live and Unknown overlap confirmations after all four publication confirmations', () => {
  const live = { ...target, transportMode: 'live' as const, mocked: false }, apply = vi.fn();
  mount(<ApigPreview preview={preview({ target: live, unknownOverlapWarning: true, acknowledgeUnknownOperationId: operationId })}
    data={state({ binding: live })} attempted={null} canWrite busy={false} onApply={apply} />);
  for (const name of [/Confirm the target, previous/, /Confirm platform Tenant minute/, /Confirm the independent policy may/, /Confirm there is no cloud CAS/]) {
    fireEvent.click(screen.getByRole('checkbox', { name }));
  }
  const button = screen.getByRole('button', { name: 'Send one explicit new APIG publication' }); expect(button).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm one cloud PUT to the Live target above' })); expect(button).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox', { name: /Confirm this is a separate new intent/ })); fireEvent.click(button);
  expect(apply).toHaveBeenCalledWith(expect.objectContaining({ confirm_live: true, confirm_unknown_overlap: true, confirm_no_cloud_cas: true }));
});
it('copies the actual original UUID and reports Clipboard failure without altering the receipt', async () => {
  const copy = vi.fn().mockRejectedValue(new Error('User denied Clipboard')); Object.defineProperty(navigator, 'clipboard', { value: { writeText: copy }, configurable: true });
  mount(<ApigReceipt operation={operation()} data={state()} canWrite busy={false} onObserve={vi.fn()} onRecover={vi.fn()} onArchive={vi.fn()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Copy original APIG request UUID' })); await screen.findByText('Copy failed; select the displayed UUID manually.');
  expect(copy).toHaveBeenCalledWith(operationId); expect(screen.getByText(operationId)).toBeInTheDocument(); expect(screen.queryByText('Original APIG request UUID copied')).not.toBeInTheDocument();
});
it('rejects a late Clipboard result from the old session', async () => {
  const pending = deferred<void>(), copy = vi.fn().mockReturnValue(pending.promise); Object.defineProperty(navigator, 'clipboard', { value: { writeText: copy }, configurable: true });
  mount(<ApigReceipt operation={operation()} data={state()} canWrite busy={false} onObserve={vi.fn()} onRecover={vi.fn()} onArchive={vi.fn()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Copy original APIG request UUID' })); await waitFor(() => expect(copy).toHaveBeenCalledTimes(1));
  act(() => useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 }));
  await act(async () => { pending.resolve(); }); expect(screen.queryByText('Original APIG request UUID copied')).not.toBeInTheDocument();
});
