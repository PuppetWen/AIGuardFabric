import { fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { schedulerManagedJobsApi as api } from '@/api/schedulerManagedJobs';
import SchedulerManagedJobsPanel from './SchedulerManagedJobsPanel';
import { operation, result, state } from './testFixtures';
import { adopt, choose, confirmApply, installHarness, mockPrepare, mount, prepare } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();
it('requires explicit kind, adopts actual CAS and submits one disabled declaration plus one immutable apply', async () => {
  const preview = mockPrepare(), apply = vi.spyOn(api, 'apply').mockImplementation(async id => result(operation({ requestId: id })));
  mount(<SchedulerManagedJobsPanel />); await prepare();
  expect(preview).toHaveBeenCalledTimes(1);
  expect(preview.mock.calls[0][0]).toMatchObject({ configuration_version: 1, expected_binding_version: 3,
    observation_id: '10000000-0000-4000-8000-000000000001', change: { action: 'create_disabled', declaration: {
      kind: 'report', name: 'Owned report', total: 1, schedule: { time_type: 1, timezone: 'UTC', time_expression: '0 0/5 * * * ?', max_attempt: 0, attempt_interval: 0 } } } });
  expect(apply).not.toHaveBeenCalled(); await confirmApply();
  await screen.findByRole('region', { name: 'Original managed request receipt' });
  expect(apply).toHaveBeenCalledTimes(1); expect(apply.mock.calls[0][1]).toEqual({ preview_id: preview.mock.calls[0][0].request_id,
    preview_fingerprint: 'c'.repeat(64), confirm_no_cloud_cas: true, confirm_callback_unknown: true, confirm_live: false, confirm_unknown_overlap: false });
  expect(apply.mock.calls[0][0]).not.toBe(preview.mock.calls[0][0].request_id);
  expect(screen.getByRole('button', { name: 'Submit one managed change' })).toBeDisabled();
});
it('keeps UTF8 and explicit creation fields bounded without inventing default task identity', async () => {
  const preview = mockPrepare(); mount(<SchedulerManagedJobsPanel />); await adopt();
  expect(screen.getByRole('button', { name: 'Preview one managed change' })).toBeDisabled();
  await choose('Actual task kind', 'report');
  fireEvent.change(screen.getByRole('textbox', { name: 'time_expression' }), { target: { value: '0 0/5 * * * ?' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Mock job name' }), { target: { value: '中'.repeat(100) } });
  expect(screen.getByRole('button', { name: 'Preview one managed change' })).toBeDisabled();
  fireEvent.change(screen.getByRole('textbox', { name: 'Mock job name' }), { target: { value: 'Owned report' } });
  fireEvent.click(screen.getByRole('checkbox', { name: 'Set explicitly timezone' }));
  expect(screen.getByRole('button', { name: 'Preview one managed change' })).toBeDisabled(); expect(preview).not.toHaveBeenCalled();
});
it('keeps the 409 draft and old binding base until explicit re-adoption and another separate action', async () => {
  const preview = vi.spyOn(api, 'preview').mockRejectedValue({ status: 409 });
  mount(<SchedulerManagedJobsPanel />); await adopt(); await choose('Actual task kind', 'report');
  fireEvent.change(screen.getByRole('textbox', { name: 'Mock job name' }), { target: { value: 'Keep this draft' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'time_expression' }), { target: { value: '0 0/5 * * * ?' } });
  fireEvent.click(screen.getByRole('button', { name: 'Preview one managed change' })); await screen.findByText('HTTP 409');
  vi.mocked(api.state).mockResolvedValue(result(state({ bindingVersion: 9 })));
  fireEvent.click(screen.getByRole('button', { name: /GET reload to compare/ }));
  await screen.findByText('Source, observation, binding version or adoption window changed. Keep the draft and explicitly adopt a new baseline.');
  expect(screen.getByRole('textbox', { name: 'Mock job name' })).toHaveValue('Keep this draft');
  expect(preview).toHaveBeenCalledTimes(1); expect(preview.mock.calls[0][0].expected_binding_version).toBe(3);
  fireEvent.click(screen.getByRole('button', { name: /Explicitly start another separate action/ })); await adopt();
  fireEvent.click(screen.getByRole('button', { name: 'Preview one managed change' }));
  await waitFor(() => expect(preview).toHaveBeenCalledTimes(2)); expect(preview.mock.calls[1][0].expected_binding_version).toBe(9);
  expect(preview.mock.calls[1][0].request_id).not.toBe(preview.mock.calls[0][0].request_id);
});
