import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { schedulerNativeApi as api } from '@/api/schedulerNative';
import SchedulerNativePanel from './SchedulerNativePanel';
import { binding, observationId, receipt, result, state } from './testFixtures';
import { installHarness, mount, readOriginal } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('keeps disabled-source historical reads and archives behind explicit reviewed generation/count', async () => {
  const tombstone = receipt({ status: 'archived', originalStatus: 'observed', archived: true, archivedAt: new Date().toISOString(),
    observation: null, available: false, current: false, archivable: false, allowedActions: ['read_receipt'] });
  vi.mocked(api.state).mockResolvedValue(result(state({ sourceTarget: null, enabled: false, canObserve: false, canBind: false,
    bindings: binding({ current: false }), recentObservations: [receipt({ current: false })] })));
  const read = vi.spyOn(api, 'receipt').mockResolvedValue(result(receipt({ current: false })));
  const archive = vi.spyOn(api, 'archive').mockResolvedValue(result({ generation: 8, archivedCount: 1, storedContentBytes: 0, stateVersion: 5 }));
  const observe = vi.spyOn(api, 'observe'); mount(<SchedulerNativePanel />); await screen.findByText('Save and enable a SchedulerX3 source first');
  fireEvent.change(screen.getByRole('textbox', { name: 'Original observation ID' }), { target: { value: observationId } });
  fireEvent.click(screen.getByRole('button', { name: /Read original observation receipt$/ })); await screen.findByText('Original observation receipt');
  const row = screen.getByRole('button', { name: 'Read original ID' }).closest('tr')!;
  fireEvent.click(within(row).getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: /Archive selected bodies/ }));
  const confirm = await screen.findByRole('button', { name: 'Confirm body archive' });
  await waitFor(() => expect(confirm).toBeVisible()); expect(archive).not.toHaveBeenCalled();
  vi.mocked(api.state).mockResolvedValue(result(state({ sourceTarget: null, enabled: false, canObserve: false, canBind: false, generation: 9 })));
  fireEvent.click(screen.getByRole('button', { name: /Reload local state/ })); await screen.findByText(/Bodies \/ archived \/ bytes \/ generation: 1 \/ 0 \/ 2000 \/ 9/);
  read.mockResolvedValue(result(tombstone)); fireEvent.click(confirm);
  await waitFor(() => expect(archive).toHaveBeenCalledWith({ expected_generation: 7, request_ids: [observationId] }));
  await screen.findByText(/No observation body is available/); expect(read).toHaveBeenCalledTimes(2); expect(observe).not.toHaveBeenCalled();
});
it('does not allow expiry alone to imply remote cancellation and leaves 409 archive selections reviewable', async () => {
  const interrupted = receipt({ status: 'interrupted', originalStatus: 'reading', observation: null, available: false, total: null,
    listingComplete: false, reason: 'Local lease expired; remote status unknown' });
  vi.mocked(api.state).mockResolvedValue(result(state({ recentObservations: [interrupted] })));
  const archive = vi.spyOn(api, 'archive').mockRejectedValue(new Error('Archive generation conflict 409'));
  vi.spyOn(api, 'receipt').mockResolvedValue(result(interrupted)); mount(<SchedulerNativePanel />); await readOriginal();
  expect(screen.getByText('Local lease expired; remote status unknown')).toBeInTheDocument();
  const row = screen.getByRole('button', { name: 'Read original ID' }).closest('tr')!;
  fireEvent.click(within(row).getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: /Archive selected bodies/ }));
  const confirm = await screen.findByRole('button', { name: 'Confirm body archive' }); await waitFor(() => expect(confirm).toBeVisible()); fireEvent.click(confirm);
  await screen.findByText('Archive generation conflict 409');
  expect(within(screen.getByRole('button', { name: 'Read original ID' }).closest('tr')!).getByRole('checkbox')).toBeChecked();
  expect(screen.getByRole('textbox', { name: 'Original observation ID' })).toHaveValue(observationId); expect(archive).toHaveBeenCalledTimes(1);
});
