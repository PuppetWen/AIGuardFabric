import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { schedulerManagedJobsApi as api } from '@/api/schedulerManagedJobs';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import type { ApiResult } from '@/api/dataSource';
import type { ManagedState, Operation } from './types';
import SchedulerManagedJobsPanel from './SchedulerManagedJobsPanel';
import { deferred, operation, operationId, result, state } from './testFixtures';
import { confirmApply, installHarness, mockPrepare, mount, prepare, readOriginal } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();
it('locks an unknown apply, keeps its original UUID through 404 and double clicks without reissue', async () => {
  mockPrepare(); const apply = vi.spyOn(api, 'apply').mockRejectedValue({ status: 503 }), read = vi.spyOn(api, 'receipt').mockRejectedValue({ status: 404 });
  mount(<SchedulerManagedJobsPanel />); await prepare(); await confirmApply(); await screen.findByText('HTTP 503');
  const id = apply.mock.calls[0][0]; expect(screen.getByRole('textbox', { name: 'Original managed request ID' })).toHaveValue(id);
  await readOriginal(id); await screen.findByText('HTTP 404'); expect(read).toHaveBeenCalledWith(id, expect.any(AbortSignal));
  fireEvent.click(screen.getByRole('button', { name: 'Submit one managed change' }));
  fireEvent.click(screen.getByRole('button', { name: 'Submit one managed change' }));
  expect(apply).toHaveBeenCalledTimes(1); expect(screen.getByRole('button', { name: /Explicitly start another separate action/ })).toBeDisabled();
  expect(screen.getByRole('textbox', { name: 'Mock job name' })).toHaveValue('Owned report');
});
it('lets explicit original GET win over a late apply response without another provider intent', async () => {
  mockPrepare(); const pending = deferred<ApiResult<Operation>>(), apply = vi.spyOn(api, 'apply').mockReturnValue(pending.promise);
  const read = vi.spyOn(api, 'receipt').mockImplementation(async id => result(operation({ requestId: id, status: 'uncertain', readback: 'unknown',
    originalWrite: { attempted: true, status: 'unknown', providerRequestId: null, authorityCurrent: false, originalDeadlineCurrent: false } })));
  mount(<SchedulerManagedJobsPanel />); await prepare(); await confirmApply(); await waitFor(() => expect(apply).toHaveBeenCalledTimes(1));
  const id = apply.mock.calls[0][0]; await readOriginal(id); await screen.findByRole('region', { name: 'Original managed request receipt' });
  await act(async () => pending.resolve(result(operation({ requestId: id }))));
  expect(screen.getByText('uncertain · complete · unknown · readback=unknown')).toBeInTheDocument();
  expect(read).toHaveBeenCalledTimes(1); expect(apply).toHaveBeenCalledTimes(1);
});
it('keeps original input identity and focus through initial GET insertion without automatic receipt reads', async () => {
  const pending = deferred<ApiResult<ManagedState>>(); vi.mocked(api.state).mockReturnValue(pending.promise);
  const read = vi.spyOn(api, 'receipt').mockResolvedValue(result(operation()));
  mount(<SchedulerManagedJobsPanel />); const input = screen.getByRole('textbox', { name: 'Original managed request ID' });
  fireEvent.change(input, { target: { value: operationId } }); input.focus();
  await act(async () => pending.resolve(result(state()))); await screen.findByRole('button', { name: 'Preview one managed change' });
  expect(screen.getByRole('textbox', { name: 'Original managed request ID' })).toBe(input); expect(input).toHaveFocus(); expect(input).toHaveValue(operationId);
  expect(read).not.toHaveBeenCalled(); await readOriginal(operationId); await screen.findByRole('region', { name: 'Original managed request receipt' });
  expect(read).toHaveBeenCalledTimes(1);
});
it('discards late apply results and the old draft during a tenant A-B-A roundtrip', async () => {
  mockPrepare(); const pending = deferred<ApiResult<Operation>>(), apply = vi.spyOn(api, 'apply').mockReturnValue(pending.promise);
  mount(<SchedulerManagedJobsPanel />); await prepare(); await confirmApply(); await waitFor(() => expect(apply).toHaveBeenCalledTimes(1));
  const oldId = apply.mock.calls[0][0];
  act(() => { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 });
    useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 3 }); });
  await act(async () => pending.resolve(result(operation({ requestId: oldId }))));
  await screen.findByRole('textbox', { name: 'Mock job name' });
  expect(screen.getByRole('textbox', { name: 'Mock job name' })).toHaveValue('');
  expect(screen.getByRole('textbox', { name: 'Original managed request ID' })).toHaveValue('');
  expect(screen.queryByRole('region', { name: 'Original managed request receipt' })).not.toBeInTheDocument();
  expect(screen.queryByText(oldId)).not.toBeInTheDocument(); expect(apply).toHaveBeenCalledTimes(1);
});
