import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { schedulerManagedJobsApi as api } from '@/api/schedulerManagedJobs';
import { schedulerNativeApi as nativeApi } from '@/api/schedulerNative';
import i18n from '@/locales/i18n';
import SchedulerManagedJobsPanel from './SchedulerManagedJobsPanel';
import { native, observation, observationId, operation, result, state, target } from './testFixtures';
import { confirmApply, installHarness, mockPrepare, mount, prepare, rights } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();
it('opens with GET only and a read-only role cannot initialize or manage jobs', async () => {
  rights.delete('alicloud:write'); rights.delete('platform:admin');
  vi.mocked(api.state).mockResolvedValue(result(state({ canManage: false, canPrepare: false })));
  const observed = vi.spyOn(nativeApi, 'observe'), preview = vi.spyOn(api, 'preview'), apply = vi.spyOn(api, 'apply');
  mount(<SchedulerManagedJobsPanel />); await screen.findByRole('button', { name: 'Preview one managed change' });
  expect(screen.getByRole('button', { name: 'Preview one managed change' })).toBeDisabled();
  expect(screen.getByRole('checkbox', { name: 'Explicitly initialize this fixed Mock example' })).toBeDisabled();
  expect(observed).not.toHaveBeenCalled(); expect(preview).not.toHaveBeenCalled(); expect(apply).not.toHaveBeenCalled();
});
it.each(['en-US', 'zh-CN'])('shows real Mock tuple and deployment/CAS boundaries in %s without business writes', async language => {
  await act(async () => { await i18n.changeLanguage(language); });
  const preview = vi.spyOn(api, 'preview'), observed = vi.spyOn(nativeApi, 'observe'); mount(<SchedulerManagedJobsPanel />);
  fireEvent.click(await screen.findByText(language === 'en-US' ? 'Managed six-job guide' : '受管六任务操作指南'));
  expect(await screen.findByText(/cn-hangzhou \/ cluster-agf-demo \/ app-agf-demo/)).toBeInTheDocument();
  expect(screen.getAllByText(/callbackBindingEnforced=false/).length).toBeGreaterThan(0);
  expect(preview).not.toHaveBeenCalled(); expect(observed).not.toHaveBeenCalled();
});
it('requires overlap confirmation even if the old unknown scope differs but its resource is the same', async () => {
  vi.mocked(api.state).mockResolvedValue(result(state({ unknownScopes: [{ requestId: '80000000-0000-4000-8000-000000000001',
    scopeId: 'changed-old-scope', expiresAt: new Date(Date.now() - 1000).toISOString(),
    resource: { tenant: target.tenant, clusterId: target.clusterId, appName: target.appName } }] })));
  mockPrepare(); const apply = vi.spyOn(api, 'apply').mockImplementation(async id => result(operation({ requestId: id })));
  mount(<SchedulerManagedJobsPanel />); await prepare();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm no cloud CAS; a read fingerprint is not an atomic cloud lock' }));
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm callback binding is unenforced and deployment/consumers remain unknown' }));
  expect(screen.getByRole('button', { name: 'Submit one managed change' })).toBeDisabled(); expect(apply).not.toHaveBeenCalled();
});
it('treats an invalid successful acknowledgement as unknown and keeps its original intent locked', async () => {
  mockPrepare(); const apply = vi.spyOn(api, 'apply').mockResolvedValue(result(operation()));
  mount(<SchedulerManagedJobsPanel />); await prepare(); await confirmApply(); await screen.findByText('Local request result unavailable / 本地请求结果不可用');
  const original = apply.mock.calls[0][0]; expect(screen.getByRole('textbox', { name: 'Original managed request ID' })).toHaveValue(original);
  expect(screen.getByRole('button', { name: /Explicitly start another separate action/ })).toBeDisabled();
  expect(screen.queryByRole('region', { name: 'Original managed request receipt' })).not.toBeInTheDocument();
});

it('initializes Mock only after explicit consent and retains each observation original UUID without a write replay', async () => {
  vi.mocked(nativeApi.state).mockResolvedValue(result(native({ latestObservation: null })));
  const observed = vi.spyOn(nativeApi, 'observe').mockImplementation(async body => result(observation({ requestId: body.request_id })));
  const prepared = vi.spyOn(api, 'preview'); mount(<SchedulerManagedJobsPanel />);
  const button = await screen.findByRole('button', { name: 'Submit a complete observation with a new ID' });
  expect(button).toBeDisabled(); expect(observed).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Explicitly initialize this fixed Mock example' })); fireEvent.click(button);
  await waitFor(() => expect(observed).toHaveBeenCalledTimes(1)); const id = observed.mock.calls[0][0].request_id;
  expect(observed.mock.calls[0][0]).toMatchObject({ configuration_version: 1, initialize_mock_fixture: true, confirm_live: false });
  fireEvent.click(await screen.findByRole('button', { name: 'Read this observation receipt' }));
  await waitFor(() => expect(nativeApi.receipt).toHaveBeenCalledWith(id, 1, expect.any(AbortSignal), 50));
  expect(observed).toHaveBeenCalledTimes(1); expect(prepared).not.toHaveBeenCalled();
});

it('loads a summarized original observation by GET before adoption and retains the edited draft', async () => {
  const full = observation();
  const { observation: body, ...summary } = full;
  vi.mocked(nativeApi.state).mockResolvedValue(result(native({ latestObservation: summary })));
  vi.mocked(nativeApi.receipt).mockResolvedValue(result({ ...summary, observation: body }));
  const observe = vi.spyOn(nativeApi, 'observe'), preview = vi.spyOn(api, 'preview'), apply = vi.spyOn(api, 'apply');
  mount(<SchedulerManagedJobsPanel />);
  const read = await screen.findByRole('button', { name: 'GET original observation (no redispatch)' });
  const adopt = screen.getByRole('button', { name: 'Adopt current observation and binding version (keep draft)' });
  expect(adopt).toBeDisabled(); expect(nativeApi.receipt).not.toHaveBeenCalled();
  expect(screen.queryByRole('group', { name: 'Managed observed job pagination' })).not.toBeInTheDocument();
  fireEvent.change(screen.getByRole('textbox', { name: 'Mock job name' }), { target: { value: 'Retained draft before GET' } });
  fireEvent.click(read);
  await waitFor(() => expect(nativeApi.receipt).toHaveBeenCalledWith(observationId, 1, expect.any(AbortSignal), 50));
  await waitFor(() => expect(adopt).toBeEnabled()); fireEvent.click(adopt);
  expect(screen.getByRole('group', { name: 'Managed observed job pagination' })).toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Mock job name' })).toHaveValue('Retained draft before GET');
  expect(nativeApi.receipt).toHaveBeenCalledTimes(1);
  expect(observe).not.toHaveBeenCalled(); expect(preview).not.toHaveBeenCalled(); expect(apply).not.toHaveBeenCalled();
});
