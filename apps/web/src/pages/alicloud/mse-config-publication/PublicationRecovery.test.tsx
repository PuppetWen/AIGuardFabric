import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { publicationApi } from './api';
import MseConfigPublicationPanel from './MseConfigPublicationPanel';
import PublicationReceipt from './PublicationReceipt';
import PublicationCandidate from './PublicationCandidate';
import PublicationPreview from './PublicationPreview';
import { installHarness, mount } from './testHarness';
import { observation, operation, operationId, policyId, preview, result, state } from './testFixtures';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

async function confirmRecovery() {
  fireEvent.click(screen.getByRole('button', { name: 'Explicit local recovery' }));
  const confirm = await screen.findByRole('button', { name: 'Confirm local recovery' });
  await waitFor(() => { expect(confirm).toBeVisible(); expect(confirm).toBeEnabled(); }); fireEvent.click(confirm);
}
it('recovers only locally after configuration is disabled, retaining pending evidence on failure and original source on success', async () => {
  vi.mocked(publicationApi.state).mockResolvedValue(result(state({ enabled: false, configured: false, binding: null, canObserve: false, canPrepare: false, canApply: false })));
  const pending = operation({ status: 'uncertain', completionState: 'pending_audit', finishedAt: null, localPublication: { status: 'pending_audit' },
    sourceCurrent: false, recoveryScopeId: null, recoveryConfigurationVersion: null, allowedActions: ['read_receipt', 'recover_local'] });
  vi.spyOn(publicationApi, 'receipt').mockResolvedValue(result(pending));
  const recover = vi.spyOn(publicationApi, 'recover').mockRejectedValueOnce(new Error('Local audit commit unavailable'))
    .mockResolvedValue(result(operation({ sourceCurrent: false, recoveryScopeId: null, recoveryConfigurationVersion: null })));
  const write = vi.spyOn(publicationApi, 'apply'), observe = vi.spyOn(publicationApi, 'observeOriginal');
  mount(<MseConfigPublicationPanel />); await screen.findByText('No valid publication target binding.');
  fireEvent.change(screen.getByRole('textbox', { name: 'Configuration publication original request UUID' }), { target: { value: operationId } });
  fireEvent.click(screen.getByRole('button', { name: 'Read original publication receipt (GET only)' })); await screen.findByText(/Cloud evidence is staged/);
  await confirmRecovery(); await screen.findByText('Local audit commit unavailable');
  expect(screen.getByText(/Cloud evidence is staged/)).toBeInTheDocument(); expect(screen.getByText('No (original receipt source retained)')).toBeInTheDocument();
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Confirm local recovery' })).not.toBeInTheDocument());
  await confirmRecovery(); await waitFor(() => expect(recover).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(screen.queryByText(/Cloud evidence is staged/)).not.toBeInTheDocument());
  expect(recover).toHaveBeenNthCalledWith(1, operationId); expect(recover).toHaveBeenNthCalledWith(2, operationId);
  expect(screen.getByText('No (original receipt source retained)')).toBeInTheDocument(); expect(screen.getByText('Unknown: no consumer receipt')).toBeInTheDocument();
  expect(write).not.toHaveBeenCalled(); expect(observe).not.toHaveBeenCalled();
});
it('does not equate an unknown cloud write with matched readback or offer unsupported recovery', () => {
  const recover = vi.fn();
  mount(<PublicationReceipt operation={operation({ status: 'uncertain', cloudWrite: { status: 'unknown' },
    localPublication: { status: 'not_staged' }, allowedActions: ['read_receipt'] })} data={state()} canRead canWrite busy={false} onObserve={vi.fn()} onRecover={recover} />);
  expect(screen.getByText('uncertain')).toBeInTheDocument(); expect(screen.getByText('matched')).toBeInTheDocument();
  expect(screen.getByText(/This cloud write has an unknown outcome/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Explicit local recovery' })).toBeDisabled(); expect(recover).not.toHaveBeenCalled();
});
it('offers only the server-authorized local recovery for an expired incomplete fact without pending evidence', async () => {
  const recover = vi.fn(), observe = vi.fn();
  mount(<PublicationReceipt operation={operation({ status: 'uncertain', completionState: 'running', finishedAt: null,
    leaseExpiresAt: new Date(Date.now() - 1000).toISOString(), cloudWrite: { status: 'unknown' }, localPublication: { status: 'not_staged' },
    allowedActions: ['read_receipt', 'recover_local'], recoveryScopeId: null, recoveryConfigurationVersion: null })}
    data={null} canRead canWrite busy={false} onObserve={observe} onRecover={recover} />);
  expect(screen.getByText(/The original lease expired while the local fact remained incomplete/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Explicitly observe original target (no rewrite)' })).toBeDisabled();
  await confirmRecovery(); expect(recover).toHaveBeenCalledTimes(1); expect(observe).not.toHaveBeenCalled();
  expect(screen.getByText('uncertain')).toBeInTheDocument();
});
it('requires both observation times after the old lease and acknowledgment of the exact unknown ID', async () => {
  const lease = new Date(Date.now() - 30000).toISOString(), at = new Date(Date.now() - 10000).toISOString();
  const unknown = operation({ status: 'uncertain', leaseExpiresAt: lease, cloudWrite: { status: 'unknown' }, allowedActions: ['read_receipt'] });
  const data = state({ unresolvedOperationId: operationId, operations: [unknown] });
  const prepare = vi.fn(), selected = [{ policyId, version: 4 }];
  const props = { data, operation: unknown, selected, onSelected: vi.fn(), rollbackId: null, onPublishMode: vi.fn(), canWrite: true, busy: false, onPrepare: prepare, onRead: vi.fn() };
  const view = mount(<PublicationCandidate {...props} baseline={{ stateVersion: 2, observation: observation({ startedAt: new Date(Date.parse(lease) - 1).toISOString(), observedAt: at }) }} />);
  await screen.findByText('Actual signed policy');
  const ack = screen.getByRole('checkbox', { name: 'Acknowledge this unknown original ID; a new publication may overlap with the old write' });
  expect(ack).toBeDisabled(); expect(screen.getByRole('button', { name: 'Prepare trusted preview (no cloud write)' })).toBeDisabled();
  view.rerender(<PublicationCandidate {...props} baseline={{ stateVersion: 2, observation: observation({ startedAt: at, observedAt: at }) }} />);
  expect(ack).toBeEnabled(); fireEvent.click(ack); fireEvent.click(screen.getByRole('button', { name: 'Prepare trusted preview (no cloud write)' }));
  expect(prepare).toHaveBeenCalledWith({ action: 'publish', policies: [{ policy_id: policyId, version: 4 }] }, true);
});
it('requires a second explicit overlap confirmation at apply even after acknowledging it at preview', async () => {
  const apply = vi.fn();
  mount(<PublicationPreview preview={preview({ unknownOverlapWarning: true, acknowledgeUnknownOperationId: operationId })} data={state()}
    attempted={null} canWrite busy={false} onApply={apply} />);
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm the target, source revisions and content hashes above' }));
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm MD5 upsert may recreate the deleted dedicated Data ID' }));
  const button = screen.getByRole('button', { name: 'Send one explicit new publication' }); expect(button).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Accept the risk of overlap between the unknown old write and the new write' })); fireEvent.click(button);
  expect(apply).toHaveBeenCalledWith(expect.objectContaining({ confirm_unknown_overlap: true, confirm_live: false }));
  await act(async () => {});
});
