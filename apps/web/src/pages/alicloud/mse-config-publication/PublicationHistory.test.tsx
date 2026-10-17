import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import PublicationHistory from './PublicationHistory';
import MseConfigPublicationPanel from './MseConfigPublicationPanel';
import { publicationApi } from './api';
import { installHarness, mount } from './testHarness';
import { observation, operation, operationId, policyId, preview, result, state, target } from './testFixtures';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('captures the reviewed archive generation and explains rollback-content loss, including while disabled', async () => {
  const archive = vi.fn(), data = state({ configured: false, enabled: false, binding: null, canPrepare: false, canApply: false, operations: [operation()] });
  const props = { canWrite: true, busy: false, onRollback: vi.fn(), onRead: vi.fn(), onArchive: archive };
  const view = mount(<PublicationHistory {...props} data={data} />);
  const row = screen.getByRole('row', { name: new RegExp(operationId) }); fireEvent.click(within(row).getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Archive 1 selected records explicitly' }));
  await screen.findByText(/Their rollback content will be lost/); expect(archive).not.toHaveBeenCalled();
  view.rerender(<PublicationHistory {...props} data={{ ...data, generation: 12 }} />);
  const confirm = await screen.findByRole('button', { name: 'Confirm removing selected rollback content' });
  await waitFor(() => expect(confirm).toBeVisible()); fireEvent.click(confirm);
  expect(archive).toHaveBeenCalledWith([operationId], 4);
});
it('uses only the trusted same-target historical ID for a new rollback preview and never sends browser content', async () => {
  const sourceId = '60000000-0000-4000-8000-000000000001';
  vi.mocked(publicationApi.state).mockResolvedValue(result(state({ history: [{ publicationId: sourceId, target, verifiedAt: new Date().toISOString(),
    contentHash: 'historical-signed-hash', contentBytes: 1000, sourcePolicyVersions: [{ policyId, version: 2 }], rollbackAvailable: true, reason: null }] })));
  const read = vi.spyOn(publicationApi, 'observe').mockResolvedValue(result(observation()));
  const prepare = vi.spyOn(publicationApi, 'preview').mockResolvedValue(result(preview({ action: 'rollback', sourcePublicationId: sourceId,
    sourcePolicyVersions: [{ policyId, version: 2 }], currentPolicyVersions: [{ policyId, version: 4 }] })));
  mount(<MseConfigPublicationPanel />);
  fireEvent.click(await screen.findByRole('button', { name: 'Explicitly read current cloud content' }));
  await screen.findByText(/Draft still uses state revision \/ observation: 2/);
  const select = screen.getByRole('button', { name: 'Select trusted source for a new rollback' });
  await waitFor(() => expect(select).toBeEnabled()); fireEvent.click(select);
  await screen.findByText(/Preparing a new publication from trusted rollback history/);
  const button = screen.getByRole('button', { name: /Prepare trusted preview \(no cloud write\)$/ });
  await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button);
  await screen.findByText('Trusted preview (no cloud write sent)');
  expect(prepare).toHaveBeenCalledWith(expect.objectContaining({ change: { action: 'rollback', publication_id: sourceId }, expected_state_version: 2 }));
  expect(prepare.mock.calls[0][0].request_id).not.toBe(sourceId); expect(prepare.mock.calls[0][0].request_id).not.toBe(read.mock.calls[0][0].request_id);
  expect(Object.keys(prepare.mock.calls[0][0].change).sort()).toEqual(['action', 'publication_id']);
});
it('does not enable rollback or archive from an unsupported or cross-target row', () => {
  const archive = vi.fn(), rollback = vi.fn();
  mount(<PublicationHistory data={state({ operations: [operation({ archivable: true, allowedActions: ['read_receipt'] })],
    history: [{ publicationId: operationId, target: { ...target, targetScopeId: policyId }, verifiedAt: new Date().toISOString(), contentHash: 'different-source',
      contentBytes: 20, sourcePolicyVersions: [], rollbackAvailable: true, reason: null }] })} canWrite busy={false} onRead={vi.fn()} onArchive={archive} onRollback={rollback} />);
  expect(screen.getByRole('button', { name: 'Select trusted source for a new rollback' })).toBeDisabled();
  expect(within(screen.getByRole('row', { name: new RegExp(operationId + ' verified') })).getByRole('checkbox')).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Archive 0 selected records explicitly' })).toBeDisabled(); expect(archive).not.toHaveBeenCalled(); expect(rollback).not.toHaveBeenCalled();
});
