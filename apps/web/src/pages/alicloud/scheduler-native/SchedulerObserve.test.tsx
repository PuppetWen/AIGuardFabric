import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { schedulerNativeApi as api } from '@/api/schedulerNative';
import type { ApiResult } from '@/api/dataSource';
import SchedulerNativePanel from './SchedulerNativePanel';
import type { ObservationReceipt } from './types';
import { deferred, job, receipt, result, state, target } from './testFixtures';
import { installHarness, mount, rights } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('permits a read role to explicitly observe Live with consent while disabling local writes', async () => {
  rights.delete('alicloud:write'); const live = { ...target, mocked: false, transportMode: 'live' as const };
  vi.mocked(api.state).mockResolvedValue(result(state({ sourceTarget: live, canInitMock: false, canBind: false })));
  const observe = vi.spyOn(api, 'observe').mockImplementation(async body => result(receipt({ requestId: body.request_id, originalTarget: live })));
  mount(<SchedulerNativePanel />); const button = await screen.findByRole('button', { name: 'Observe with a new request ID' });
  expect(button).toBeDisabled(); fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm reading this live cloud source' })); fireEvent.click(button);
  await waitFor(() => expect(observe).toHaveBeenCalledTimes(1));
  expect(observe).toHaveBeenCalledWith(expect.objectContaining({ configuration_version: 1, confirm_live: true, initialize_mock_fixture: false }));
  expect(screen.getByRole('button', { name: 'Save local associations' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Disable local associations' })).toBeDisabled();
  expect(screen.queryByRole('checkbox', { name: /Explicitly initialize/ })).not.toBeInTheDocument();
});
it('initializes Mock only by explicit consent and preserves a failed UUID for GET without redispatch', async () => {
  const secure = vi.spyOn(crypto, 'randomUUID').mockImplementation(() => { throw new Error('LAN HTTP is not a secure context'); });
  const observe = vi.spyOn(api, 'observe').mockRejectedValue(new Error('Observation response unavailable'));
  const read = vi.spyOn(api, 'receipt').mockImplementation(async id => result(receipt({ requestId: id, status: 'failed', originalStatus: 'failed',
    observation: null, available: false, listingComplete: false })));
  mount(<SchedulerNativePanel />); await screen.findByText(target.appName); expect(observe).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('checkbox', { name: /Explicitly initialize this source/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Observe with a new request ID' })); await screen.findByText('Observation response unavailable');
  const id = observe.mock.calls[0][0].request_id; expect(id).toMatch(/^[0-9a-f-]{36}$/);
  expect(screen.getByRole('textbox', { name: 'Original observation ID' })).toHaveValue(id);
  expect(observe.mock.calls[0][0]).toMatchObject({ initialize_mock_fixture: true, confirm_live: false });
  fireEvent.click(screen.getByRole('button', { name: /Read original observation receipt$/ })); await screen.findByText('Original observation receipt');
  expect(read).toHaveBeenCalledWith(id, 1, expect.any(AbortSignal), 50); expect(observe).toHaveBeenCalledTimes(1); expect(secure).not.toHaveBeenCalled();
});
it('blocks repeat observation clicks while busy and lets an explicit original GET supersede a late response', async () => {
  const pending = deferred<ApiResult<ObservationReceipt>>(), observe = vi.spyOn(api, 'observe').mockReturnValue(pending.promise);
  const read = vi.spyOn(api, 'receipt').mockImplementation(async id => result(receipt({ requestId: id, status: 'reading', originalStatus: 'reading',
    observation: null, available: false, listingComplete: false, archivable: false })));
  mount(<SchedulerNativePanel />); await screen.findByText(target.appName);
  const button = screen.getByRole('button', { name: 'Observe with a new request ID' }); fireEvent.click(button); fireEvent.click(button);
  await waitFor(() => expect(observe).toHaveBeenCalledTimes(1)); const id = observe.mock.calls[0][0].request_id;
  fireEvent.click(screen.getByRole('button', { name: /Read original observation receipt$/ })); await screen.findByText('Original observation receipt');
  await act(async () => pending.resolve(result(receipt({ requestId: id }))));
  expect(read).toHaveBeenCalledTimes(1); expect(screen.queryByText(`Actual job 9007199254741002`)).not.toBeInTheDocument();
  expect(observe).toHaveBeenCalledTimes(1);
});
it('clears prior Live consent when the source fingerprint changes', async () => {
  const live = { ...target, mocked: false, transportMode: 'live' as const };
  vi.mocked(api.state).mockResolvedValue(result(state({ sourceTarget: live })));
  mount(<SchedulerNativePanel />); await screen.findByText(target.appName);
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm reading this live cloud source' }));
  vi.mocked(api.state).mockResolvedValue(result(state({ sourceTarget: { ...live, fingerprint: 'new-account-fingerprint', configurationVersion: 2 } })));
  fireEvent.click(screen.getByRole('button', { name: /Reload local state/ }));
  await waitFor(() => expect(screen.getByRole('checkbox', { name: 'Confirm reading this live cloud source' })).not.toBeChecked());
  expect(screen.getByRole('button', { name: 'Observe with a new request ID' })).toBeDisabled();
});
it('does not label a server-authorized loopback_test mode as Live or infer Mock initialization', async () => {
  const loopback = { ...target, mocked: false, transportMode: 'loopback_test' as const };
  vi.mocked(api.state).mockResolvedValue(result(state({ sourceTarget: loopback, canInitMock: false })));
  const observe = vi.spyOn(api, 'observe').mockImplementation(async body => result(receipt({ requestId: body.request_id, originalTarget: loopback })));
  mount(<SchedulerNativePanel />); await screen.findByText('loopback_test');
  expect(screen.queryByRole('checkbox', { name: 'Confirm reading this live cloud source' })).not.toBeInTheDocument();
  expect(screen.queryByRole('checkbox', { name: /Explicitly initialize/ })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Observe with a new request ID' }));
  await waitFor(() => expect(observe).toHaveBeenCalledWith(expect.objectContaining({ confirm_live: false, initialize_mock_fixture: false })));
});
it('keeps the server Observe receipt page width for subsequent GET paging without redispatch', async () => {
  const observed = receipt(), nextId = '9007199254741103';
  const observe = vi.spyOn(api, 'observe').mockImplementation(async body => result(receipt({ requestId: body.request_id,
    total: 101, observation: { ...observed.observation!, pageSize: 100, total: 101, totalPages: 2 } })));
  const read = vi.spyOn(api, 'receipt').mockImplementation(async id => result(receipt({ requestId: id, total: 101,
    observation: { ...observed.observation!, jobs: [job(nextId)], page: 2, pageSize: 100, total: 101, totalPages: 2 } })));
  mount(<SchedulerNativePanel />); await screen.findByText(target.appName);
  fireEvent.click(screen.getByRole('button', { name: 'Observe with a new request ID' })); await screen.findByText('Original observation receipt');
  const pagination = screen.getByLabelText('Observed job pagination'); fireEvent.click(pagination.querySelector('[title="2"]')!);
  await screen.findByText(`Actual job ${nextId}`);
  expect(read).toHaveBeenCalledWith(observe.mock.calls[0][0].request_id, 2, expect.any(AbortSignal), 100);
  expect(observe).toHaveBeenCalledTimes(1);
});
