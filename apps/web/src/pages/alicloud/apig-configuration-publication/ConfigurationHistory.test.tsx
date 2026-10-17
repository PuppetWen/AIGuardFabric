import { fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { apigConfigurationApi as api } from '@/api/apigConfigurationPublication';
import ApigConfigurationPublicationPanel from './ApigConfigurationPublicationPanel';
import ConfigurationHistory from './ConfigurationHistory';
import { operation, operationId, preview, result, state } from './testFixtures';
import { installHarness, mount } from './testHarness';
import { adopt, prepare, read } from './testActions';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('uses a trusted history ID and fresh adopted observation for rollback, without resending an old operation', async () => {
  vi.mocked(api.state).mockResolvedValue(result(state({ history: [{ publicationId: operationId, target: operation().target, verifiedAt: operation().finishedAt!,
    contentHash: 'history-hash', diff: preview().diff, rollbackAvailable: true, reason: null }] })));
  const prepared = vi.spyOn(api, 'preview').mockResolvedValue(result(preview({ action: 'rollback', sourcePublicationId: operationId }))), applied = vi.spyOn(api, 'apply');
  mount(<ApigConfigurationPublicationPanel />); await adopt(); fireEvent.click(screen.getByRole('button', { name: 'Choose trusted public configuration rollback' })); await prepare();
  expect(prepared).toHaveBeenCalledWith(expect.objectContaining({ change: { action: 'rollback', publication_id: operationId }, expected_state_version: 2 })); expect(applied).not.toHaveBeenCalled();
});
it('captures archive generation and selected IDs at explicit review even when newer local state arrives', async () => {
  const archive = vi.fn().mockResolvedValue(undefined), initial = state({ operations: [operation()] });
  const rendered = mount(<ConfigurationHistory data={initial} canWrite busy={false} held={false} onRead={vi.fn()} onRollback={vi.fn()} onArchive={archive} />);
  const checkbox = screen.getByRole('checkbox'); fireEvent.click(checkbox); fireEvent.click(screen.getByRole('button', { name: 'Explicitly archive selected configuration details' }));
  await screen.findByText('Review 1 requests at archive generation 3; cloud configuration is unchanged.');
  rendered.rerender(<ConfigurationHistory data={{ ...initial, generation: 9 }} canWrite busy={false} held={false} onRead={vi.fn()} onRollback={vi.fn()} onArchive={archive} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Confirm loss of selected configuration rollback bodies and archive' }));
  await waitFor(() => expect(archive).toHaveBeenCalledWith([operationId], 3));
});
it('allows explicit disabled-source archive, then reads the permanent original UUID tombstone', async () => {
  vi.mocked(api.state).mockResolvedValue(result(state({ enabled: false, binding: null, observation: null, canPrepare: false, canApply: false, canObserve: false, canInitializeMockFixture: false })));
  const receipt = vi.spyOn(api, 'receipt').mockResolvedValueOnce(result(operation({ sourceCurrent: false }))).mockResolvedValue(result(operation({ status: 'archived', originalStatus: 'verified', archived: true,
    archivedAt: new Date().toISOString(), archivable: false, sourceCurrent: false, allowedActions: ['read_receipt'] })));
  const archive = vi.spyOn(api, 'archive').mockResolvedValue(result({ generation: 4, archivedCount: 1, archivedRequestIds: [operationId], unchanged: false }));
  mount(<ApigConfigurationPublicationPanel />); await read(operationId);
  fireEvent.click(screen.getByRole('button', { name: 'Explicitly archive original configuration detail (1 request)' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Confirm archiving this 1 configuration detail' })); await screen.findByText('verified / archived');
  expect(archive).toHaveBeenCalledWith({ expected_generation: 3, request_ids: [operationId] }); expect(receipt).toHaveBeenCalledTimes(2);
});
