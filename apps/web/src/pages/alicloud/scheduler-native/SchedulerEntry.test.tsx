import { fireEvent, screen } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import { schedulerNativeApi as api } from '@/api/schedulerNative';
import AliCloudPage from '@/pages/AliCloudPage';
import { SchedulerGuide } from '../SchedulerGuide';
import { installHarness, mount } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
vi.mock('@/api/client', () => ({ api: {}, useApiQuery: () => ({ data: { data: [] }, isLoading: false, error: null, refetch: vi.fn() }) }));
vi.mock('../CloudConnections', () => ({ default: () => null }));
vi.mock('../AgentTeamsAuditPanel', () => ({ default: () => <div>Read-only audit panel</div> }));
vi.mock('../TeamTable', () => ({ TeamTable: () => null }));
vi.mock('../CrossCallsPanel', () => ({ CrossCallsPanel: () => null }));
vi.mock('../BindingsPanel', () => ({ BindingsPanel: () => null }));
vi.mock('../SelfCheckPanel', () => ({ SelfCheckPanel: () => null }));
installHarness();
function LocationProbe() { return <output aria-label="Current tab parameters">{useLocation().search}</output>; }

it('opens the real Scheduler tab with a pure local GET and preserves unrelated parameters across tab navigation', async () => {
  const calls = [vi.spyOn(api, 'observe'), vi.spyOn(api, 'bind'), vi.spyOn(api, 'archive'), vi.spyOn(api, 'receipt')];
  mount(<MemoryRouter initialEntries={['/alicloud?tab=scheduler-native&keep=user-view']}><AliCloudPage /><LocationProbe /></MemoryRouter>);
  expect(await screen.findByRole('tab', { name: 'Scheduler job connection' })).toHaveAttribute('aria-selected', 'true');
  await screen.findByText('actual-configured-application'); expect(api.state).toHaveBeenCalledWith(expect.any(AbortSignal));
  calls.forEach(call => expect(call).not.toHaveBeenCalled());
  fireEvent.click(screen.getByRole('tab', { name: 'Messages and call audit' })); await screen.findByText('Read-only audit panel');
  const params = new URLSearchParams(screen.getByLabelText('Current tab parameters').textContent ?? '');
  expect(params.get('tab')).toBe('audit'); expect(params.get('keep')).toBe('user-view');
  fireEvent.click(screen.getByRole('tab', { name: 'Scheduler job connection' }));
  expect(screen.getByRole('tab', { name: 'Scheduler job connection' })).toHaveAttribute('aria-selected', 'true');
  calls.forEach(call => expect(call).not.toHaveBeenCalled());
});
it('links the existing preparation guide to the native tab without making preparation a cloud registration proof', async () => {
  const observe = vi.spyOn(api, 'observe'); mount(<SchedulerGuide />);
  expect(screen.getByRole('link', { name: 'Observe actual jobs and save local bindings (no automatic deployment or cloud registration)' }))
    .toHaveAttribute('href', '/alicloud?tab=scheduler-native');
  expect(screen.getByRole('link', { name: 'Open managed jobs: preview changes, enable/disable, original-ID recovery and history archive' }))
    .toHaveAttribute('href', '/alicloud?tab=scheduler-managed');
  expect(screen.getByText('Verify managed jobs and actual deployment separately')).toBeInTheDocument();
  expect(screen.getByText(/The Live HTTP creation payload contract remains unverified and creation is rejected/)).toBeInTheDocument();
  expect(screen.getByText(/Observation, local binding and registration do not establish deployed callbacks or successful business execution/)).toBeInTheDocument();
  expect(api.state).not.toHaveBeenCalled(); expect(observe).not.toHaveBeenCalled();
});
