import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { schedulerManagedJobsApi as api } from '@/api/schedulerManagedJobs';
import { schedulerNativeApi as nativeApi } from '@/api/schedulerNative';
import SchedulerManagedJobsPanel from './SchedulerManagedJobsPanel';
import { native, operation, operationId, result, state } from './testFixtures';
import { installHarness, mount, readOriginal } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();
it('requires reviewed count/loss confirmation and preserves the reviewed CAS across a newer GET', async () => {
  const row = operation(); vi.mocked(api.state).mockResolvedValue(result(state({ operations: [row], operationTotal: 1, generation: 4 })));
  const archive = vi.spyOn(api, 'archive').mockRejectedValue({ status: 409 });
  mount(<SchedulerManagedJobsPanel />); const box = await screen.findByRole('checkbox', { name: `Archive ${operationId}` }); fireEvent.click(box);
  fireEvent.click(screen.getByRole('button', { name: 'Review selected body archive' }));
  expect(screen.getByRole('button', { name: 'Archive reviewed bodies' })).toBeDisabled();
  vi.mocked(api.state).mockResolvedValue(result(state({ operations: [row], operationTotal: 1, generation: 7 })));
  fireEvent.click(screen.getByRole('button', { name: /GET reload to compare/ }));
  await screen.findByText('The ledger generation changed. This action retains the reviewed generation; a conflict keeps choices and requires a new review.');
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm irreversible body loss and selected count' }));
  fireEvent.click(screen.getByRole('button', { name: 'Archive reviewed bodies' }));
  const confirm = await screen.findByRole('button', { name: 'Confirm loss and archive' }); await waitFor(() => expect(confirm).toBeVisible()); fireEvent.click(confirm);
  await screen.findByText('HTTP 409'); expect(archive).toHaveBeenCalledWith([operationId], 4); expect(box).toBeChecked();
});
it('offers server-approved pure local recovery even with a disabled source', async () => {
  const row = operation({ status: 'uncertain', completionState: 'pending_audit', finishedAt: null, sourceCurrent: null,
    allowedActions: ['read_receipt', 'recover_local'], archivable: false });
  vi.mocked(api.state).mockResolvedValue(result(state({ target: null, sourceState: 'disabled_or_missing', canPrepare: false })));
  vi.mocked(nativeApi.state).mockResolvedValue(result(native({ sourceTarget: null, enabled: false, canObserve: false })));
  vi.spyOn(api, 'receipt').mockResolvedValue(result(row)); const recover = vi.spyOn(api, 'recover').mockResolvedValue(result(operation({ sourceCurrent: null })));
  mount(<SchedulerManagedJobsPanel />); await readOriginal(operationId);
  const region = await screen.findByRole('region', { name: 'Original managed request receipt' });
  const button = within(region).getByRole('button', { name: 'Recover local completion/audit explicitly (no cloud)' });
  expect(button).toBeEnabled(); fireEvent.click(button); await waitFor(() => expect(recover).toHaveBeenCalledWith(operationId));
  expect(screen.getByRole('button', { name: 'Preview one managed change' })).toBeDisabled();
});
