import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { apigPublicationApi as api } from '@/api/apigPolicyPublication';
import ApigPolicyPublicationPanel from './ApigPolicyPublicationPanel';
import ApigHistory from './ApigHistory';
import { observation, operation, operationId, preview, result, state, target } from './testFixtures';
import { installHarness, mount } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('prepares trusted historical threshold rollback against a fresh baseline without a cloud write', async () => {
  const history = { publicationId: operationId, target, verifiedAt: new Date().toISOString(), contentHash: 'trusted-hash', contentBytes: 220,
    sourcePolicyVersions: [], rollbackAvailable: true, reason: null };
  vi.mocked(api.state).mockResolvedValue(result(state({ history: [history] })));
  const prepare = vi.spyOn(api, 'preview').mockResolvedValue(result(preview({ action: 'rollback', sourcePublicationId: operationId }))), apply = vi.spyOn(api, 'apply');
  mount(<ApigPolicyPublicationPanel />); fireEvent.click(await screen.findByRole('button', { name: 'Choose trusted threshold rollback' }));
  expect(screen.getByText(`Retained trusted threshold rollback source: ${operationId}`)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Explicitly adopt the latest observation as the draft baseline' }));
  fireEvent.click(screen.getByRole('button', { name: 'Prepare trusted APIG preview (no cloud write)' })); await screen.findByText('Trusted APIG preview (no cloud write sent)');
  expect(prepare).toHaveBeenCalledWith(expect.objectContaining({ observation_id: observation().id, expected_state_version: 2, change: { action: 'rollback', publication_id: operationId } }));
  expect(apply).not.toHaveBeenCalled();
});
it('shows the server rollback-unavailable reason and disallows selection', () => {
  mount(<ApigHistory data={state({ history: [{ publicationId: operationId, target, verifiedAt: new Date().toISOString(), contentHash: 'retained-hash',
    contentBytes: 100, sourcePolicyVersions: [], rollbackAvailable: false, reason: 'Current mode does not support the historical threshold slot' }] })}
    canWrite busy={false} onRead={vi.fn()} onRollback={vi.fn()} onArchive={vi.fn()} />);
  expect(screen.getByText(/Current mode does not support the historical threshold slot/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Choose trusted threshold rollback' })).toBeDisabled();
});
it('archives only explicitly selected terminal details with the reviewed count and generation, even if state changes while confirmation is open', async () => {
  const publish = operation(), running = operation({ requestId: '20000000-0000-4000-8000-000000000099', completionState: 'running', archivable: false, allowedActions: ['read_receipt'] });
  const props = { canWrite: true, busy: false, onRead: vi.fn(), onRollback: vi.fn(), onArchive: vi.fn().mockResolvedValue(undefined) };
  const data = state({ operations: [publish, running], detailedRunCount: 2 }), view = mount(<ApigHistory {...props} data={data} />);
  const published = screen.getByRole('row', { name: new RegExp(`${operationId} verified`) }), active = screen.getByRole('row', { name: /000000000099 verified/ });
  expect(within(active).getByRole('checkbox')).toBeDisabled(); expect(props.onArchive).not.toHaveBeenCalled();
  fireEvent.click(within(published).getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Explicitly archive selected APIG details' }));
  const button = await screen.findByRole('button', { name: 'Confirm loss of selected rollback bodies and archive' });
  await waitFor(() => { expect(button).toBeVisible(); expect(button).toBeEnabled(); });
  expect(screen.getByText('Review 1 requests at archive generation 3; cloud configuration is unchanged.')).toBeInTheDocument();
  view.rerender(<ApigHistory {...props} data={{ ...data, generation: 9 }} />);
  fireEvent.click(screen.getByRole('button', { name: 'Confirm loss of selected rollback bodies and archive' }));
  await waitFor(() => expect(props.onArchive).toHaveBeenCalledWith([operationId], 3));
});
it('reads and archives a terminal original UUID outside the recent list while disabled, then reads its permanent tombstone without dispatch', async () => {
  vi.mocked(api.state).mockResolvedValue(result(state({ enabled: false, canObserve: false, canApply: false, canPrepare: false, operations: [], observation: null })));
  const archived = operation({ status: 'archived', originalStatus: 'verified', archived: true, archivedAt: new Date().toISOString(), archivable: false, allowedActions: ['read_receipt'] });
  const read = vi.spyOn(api, 'receipt').mockResolvedValueOnce(result(operation())).mockResolvedValue(result(archived));
  const archive = vi.spyOn(api, 'archive').mockResolvedValue(result({ generation: 4, archivedCount: 1, archivedRequestIds: [operationId], unchanged: false }));
  const apply = vi.spyOn(api, 'apply'), observe = vi.spyOn(api, 'observe'); mount(<ApigPolicyPublicationPanel />);
  await waitFor(() => expect(screen.getByRole('button', { name: /Refresh APIG local state to compare/ })).not.toHaveClass('ant-btn-loading'));
  const input = screen.getByRole('textbox', { name: 'APIG publication original request UUID' });
  fireEvent.change(input, { target: { value: operationId } }); expect(input).toHaveValue(operationId);
  const button = screen.getByRole('button', { name: /Read original APIG receipt \(GET only\)$/ }); expect(button).toBeEnabled(); fireEvent.click(button);
  await waitFor(() => expect(read).toHaveBeenCalledWith(operationId, expect.any(AbortSignal))); await screen.findByText('Original APIG request receipt');
  fireEvent.click(screen.getByRole('button', { name: 'Explicitly archive original APIG detail (1 request)' }));
  const confirm = await screen.findByRole('button', { name: 'Confirm archiving this 1 request' }); await waitFor(() => expect(confirm).toBeVisible()); fireEvent.click(confirm);
  await screen.findByText('verified / archived'); expect(archive).toHaveBeenCalledWith({ expected_generation: 3, request_ids: [operationId] });
  expect(read).toHaveBeenCalledTimes(2); expect(apply).not.toHaveBeenCalled(); expect(observe).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Explicitly archive original APIG detail (1 request)' })).toBeDisabled();
});
