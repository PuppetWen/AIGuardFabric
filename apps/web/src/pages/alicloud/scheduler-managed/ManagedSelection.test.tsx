import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { schedulerManagedJobsApi as api } from '@/api/schedulerManagedJobs';
import { schedulerNativeApi as nativeApi } from '@/api/schedulerNative';
import SchedulerManagedJobsPanel from './SchedulerManagedJobsPanel';
import { native, observation, observationId, preview, result, selectedJob } from './testFixtures';
import { adopt, choose, installHarness, mount } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();
it('preserves actual int64 job selection across GET pages and updates only the explicitly chosen retry field', async () => {
  const original = observation(), bigId = selectedJob().id;
  const first = observation({ total: 51, observation: { ...original.observation!, jobs: [], total: 51, totalPages: 2 } });
  vi.mocked(nativeApi.state).mockResolvedValue(result(native({ latestObservation: first })));
  vi.mocked(nativeApi.receipt).mockImplementation(async (id, page) => result(observation({ requestId: id, total: 51,
    observation: { ...original.observation!, page: page ?? 1, jobs: page === 2 ? [selectedJob()] : [], total: 51, totalPages: 2 } })));
  const prepared = vi.spyOn(api, 'preview').mockImplementation(async body => result(preview({ id: body.request_id })));
  mount(<SchedulerManagedJobsPanel />); await adopt(); await choose('Actual task kind', 'report');
  await choose('Single action', 'Update disabled job calendar/retry');
  fireEvent.click(within(screen.getByRole('group', { name: 'Managed observed job pagination' })).getByTitle('2')); await waitFor(() => expect(nativeApi.receipt).toHaveBeenCalledWith(observationId, 2, expect.any(AbortSignal), 50));
  await choose('Observed HTTP Job ID', `Actual job ${bigId} · ${bigId} · disabled`);
  fireEvent.click(within(screen.getByRole('group', { name: 'Managed observed job pagination' })).getByTitle('1')); await waitFor(() => expect(nativeApi.receipt).toHaveBeenLastCalledWith(observationId, 1, expect.any(AbortSignal), 50));
  for (const field of ['time_type', 'time_expression', 'timezone', 'calendar', 'attempt_interval']) fireEvent.click(screen.getByRole('checkbox', { name: `Set explicitly ${field}` }));
  fireEvent.change(screen.getByRole('textbox', { name: 'max_attempt' }), { target: { value: '2' } });
  const button = screen.getByRole('button', { name: 'Preview one managed change' }); await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button);
  await waitFor(() => expect(prepared).toHaveBeenCalledTimes(1));
  expect(prepared.mock.calls[0][0]).toMatchObject({ change: { action: 'update_schedule', patch: { max_attempt: 2 } },
    selection: { kind: 'report', app_id: '9007199254740993', job_id: bigId, observation_fingerprint: 'b'.repeat(64) } });
  expect(Object.keys(prepared.mock.calls[0][0].change)).toEqual(['action', 'patch']);
});
it('retains an enabled job choice but cannot implicitly disable it during schedule update', async () => {
  const actual = selectedJob(); actual.enabled = true; actual.status = 1;
  const base = observation(), observed = observation({ observation: { ...base.observation!, jobs: [actual] } });
  vi.mocked(nativeApi.state).mockResolvedValue(result(native({ latestObservation: observed })));
  vi.mocked(nativeApi.receipt).mockResolvedValue(result(observed));
  const prepared = vi.spyOn(api, 'preview'); mount(<SchedulerManagedJobsPanel />); await adopt(); await choose('Actual task kind', 'report');
  await choose('Single action', 'Update disabled job calendar/retry');
  await choose('Observed HTTP Job ID', `Actual job ${actual.id} · ${actual.id} · enabled`);
  expect(screen.getByRole('button', { name: 'Preview one managed change' })).toBeDisabled(); expect(prepared).not.toHaveBeenCalled();
});
