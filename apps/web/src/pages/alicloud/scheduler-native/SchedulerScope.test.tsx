import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { schedulerNativeApi as api } from '@/api/schedulerNative';
import type { ApiResult } from '@/api/dataSource';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import SchedulerNativePanel from './SchedulerNativePanel';
import type { ObservationReceipt, SchedulerState } from './types';
import { deferred, observationId, receipt, result, state, target } from './testFixtures';
import { installHarness, mount } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('enters through a local GET without observing, binding or initializing and preserves the real boundary', async () => {
  const calls = [vi.spyOn(api, 'observe'), vi.spyOn(api, 'bind'), vi.spyOn(api, 'archive'), vi.spyOn(api, 'receipt')];
  mount(<SchedulerNativePanel />); await screen.findByText(target.appName);
  expect(api.state).toHaveBeenCalledWith(expect.any(AbortSignal));
  calls.forEach(call => expect(call).not.toHaveBeenCalled());
  expect(screen.getByText(/Callback binding is not enforced/)).toBeInTheDocument();
  expect(screen.getByText(/deploymentVerified=unknown/)).toBeInTheDocument();
});
it('preserves an early recovery input and focus when the initial state finishes without auto-reading', async () => {
  const pending = deferred<ApiResult<SchedulerState>>(); vi.mocked(api.state).mockReturnValueOnce(pending.promise);
  const read = vi.spyOn(api, 'receipt').mockResolvedValue(result(receipt())); mount(<SchedulerNativePanel />);
  const input = screen.getByRole('textbox', { name: 'Original observation ID' });
  fireEvent.change(input, { target: { value: observationId } }); act(() => input.focus());
  await act(async () => pending.resolve(result(state()))); await screen.findByText(target.appName);
  expect(screen.getByRole('textbox', { name: 'Original observation ID' })).toBe(input); expect(input).toHaveFocus();
  expect(input).toHaveValue(observationId); expect(read).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: /Read original observation receipt$/ }));
  await screen.findByText('Original observation receipt'); expect(read).toHaveBeenCalledWith(observationId, 1, expect.any(AbortSignal), 50);
});
it.each(['tenant', 'session', 'tenant-roundtrip'])('discards and aborts a late receipt across a %s change', async change => {
  const pending = deferred<ApiResult<ObservationReceipt>>(), read = vi.spyOn(api, 'receipt').mockReturnValue(pending.promise);
  mount(<SchedulerNativePanel />); await screen.findByText(target.appName);
  fireEvent.change(screen.getByRole('textbox', { name: 'Original observation ID' }), { target: { value: observationId } });
  fireEvent.click(screen.getByRole('button', { name: /Read original observation receipt$/ })); await waitFor(() => expect(read).toHaveBeenCalledTimes(1));
  const signal = read.mock.calls[0][2];
  act(() => {
    if (change === 'session') useAuthStore.setState({ sessionGeneration: 2 });
    else { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 });
      if (change === 'tenant-roundtrip') useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 3 }); }
  });
  await act(async () => pending.resolve(result(receipt())));
  expect(signal?.aborted).toBe(true); expect(screen.queryByText('Original observation receipt')).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Original observation ID' })).toHaveValue(''); expect(read).toHaveBeenCalledTimes(1);
});
it('aborts a prior tenant state read and never publishes its source into the new tenant', async () => {
  const pending = deferred<ApiResult<SchedulerState>>(); vi.mocked(api.state).mockReturnValueOnce(pending.promise);
  mount(<SchedulerNativePanel />); await waitFor(() => expect(api.state).toHaveBeenCalledTimes(1));
  const signal = vi.mocked(api.state).mock.calls[0][0];
  vi.mocked(api.state).mockResolvedValue(result(state({ sourceTarget: { ...target, appName: 'Current tenant app' } })));
  act(() => useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 }));
  await screen.findByText('Current tenant app');
  await act(async () => pending.resolve(result(state({ sourceTarget: { ...target, appName: 'Prior tenant app' } }))));
  expect(signal?.aborted).toBe(true); expect(screen.queryByText('Prior tenant app')).not.toBeInTheDocument();
});
