import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ConfigProvider } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { onboardingApi } from '@/api/onboarding';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import type { ConnectionPlan, OnboardingTarget, PlanRequest } from '@/types/onboarding';
import type { ApiResult } from '@/api/dataSource';
import i18n from '@/locales/i18n';
import { OnboardingWizard } from './OnboardingWizard';

vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
const original = useAuthStore.getState(), clients: QueryClient[] = [];
const result = (data: ConnectionPlan): ApiResult<ConnectionPlan> => ({ data, meta: { source: 'live', at: 0, elapsedMs: 0 } });
const source = { sourceId: '01921d34-0000-7000-8000-000000000001', bindingId: '01921d34-0000-7000-8000-000000000002',
  scopeId: '01921d34-0000-7000-8000-000000000003', mocked: true, name: 'Actual bound source', workers: [{ name: 'Actual Worker', teams: ['Actual Team'] }] };
function plan(target: OnboardingTarget = 'collector', patch: Partial<ConnectionPlan> = {}): ConnectionPlan {
  return { agentId: '', mode: target.includes('startup') ? 'sdk-inject' : 'sidecar', target, ready: false,
    endpoint: 'https://platform.example.test', envSnippet: '', steps: [], rollout: 'manual', platform: 'windows-amd64',
    estimatedDowntimeSec: null, artifactUrl: null, artifactSha256: null, availableTargets: [target], links: [],
    sdkSources: [source], configurationJson: null, keyEnv: null, ...patch };
}
beforeEach(async () => {
  await i18n.changeLanguage('en-US'); useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 1 });
  vi.mocked(useSessionAccess, { partial: true }).mockReturnValue({ has: () => true, isLoading: false });
  vi.spyOn(onboardingApi, 'choices').mockResolvedValue(result(plan('python-startup')));
  vi.spyOn(onboardingApi, 'plan').mockImplementation(async input => result(plan(input.target)));
});
afterEach(async () => { cleanup(); clients.forEach(client => client.clear()); clients.length = 0;
  vi.restoreAllMocks(); useAuthStore.setState(original); await act(async () => { await i18n.changeLanguage('zh-CN'); }); });
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } }); clients.push(client);
  render(<QueryClientProvider client={client}><ConfigProvider theme={{ token: { motion: false } }}>
    <MemoryRouter><OnboardingWizard agent={null} onClose={() => undefined} /></MemoryRouter>
  </ConfigProvider></QueryClientProvider>);
}
async function select(label: string, value: string) {
  fireEvent.mouseDown(screen.getByRole('combobox', { name: label }));
  fireEvent.click(await screen.findByText(value, { selector: '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content' }));
}
function fill(label: string, value: string) { fireEvent.change(screen.getByRole('textbox', { name: label }), { target: { value } }); }

it('offers concrete mechanisms without automatically generating a plan or requesting business', async () => {
  mount(); expect(onboardingApi.plan).not.toHaveBeenCalled(); expect(onboardingApi.choices).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('radio', { name: 'SDK startup injection' }));
  await select('Connection target', 'node-cjs-startup');
  expect(screen.getByRole('textbox', { name: 'Absolute CommonJS target file' })).toHaveValue('');
  expect(screen.queryByRole('textbox', { name: 'Exact model ID' })).not.toBeInTheDocument();
  expect(onboardingApi.plan).not.toHaveBeenCalled();
});
it('sends only the explicitly selected source, Worker and qualified Python entry with exact snake keys', async () => {
  mount(); fireEvent.click(screen.getByRole('radio', { name: 'SDK startup injection' }));
  fireEvent.click(screen.getByRole('button', { name: 'Load current sources and Workers (read only)' }));
  await waitFor(() => expect(onboardingApi.choices).toHaveBeenCalledTimes(1));
  await select('Current audit source', `Actual bound source · Mock · ${source.sourceId}`); await select('Worker', 'Actual Worker'); await select('Team', 'Actual Team');
  for (const [label, value] of [['Static operation tag', 'actual-task'], ['Actual target module', 'business.tasks'], ['Actual callable / export path', 'run'],
    ['Original entry (Python module / absolute Node script)', 'business.main'], ['Absolute installed SDK directory', 'E:/owned/sdk'],
    ['Absolute application-owned queue directory', 'E:/owned/queue'], ['Absolute noncredential configuration file', 'E:/owned/startup.json']]) fill(label, value);
  fireEvent.click(screen.getByRole('button', { name: 'Generate read-only connection plan' }));
  await waitFor(() => expect(onboardingApi.plan).toHaveBeenCalledTimes(1));
  const sent: PlanRequest = vi.mocked(onboardingApi.plan).mock.calls[0][0];
  expect(sent.target).toBe('python-startup'); expect(sent.model).toBeUndefined(); expect(sent.sdk).toMatchObject({ source_id: source.sourceId,
    binding_id: source.bindingId, worker: 'Actual Worker', team: 'Actual Team', module: 'business.tasks', entry: 'business.main', kind: 'task' });
  expect(sent.sdk).not.toHaveProperty('key'); expect(sent.sdk).not.toHaveProperty('original_args');
});
it('does not fetch source choices or dispatch a plan when additional inventory read grants are missing', async () => {
  vi.mocked(useSessionAccess, { partial: true }).mockReturnValue({ has: permission => permission === 'agents:read', isLoading: false });
  mount(); fireEvent.click(screen.getByRole('radio', { name: 'SDK startup injection' }));
  expect(screen.getByRole('button', { name: 'Load current sources and Workers (read only)' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Generate read-only connection plan' })).toBeDisabled();
  expect(onboardingApi.choices).not.toHaveBeenCalled(); expect(onboardingApi.plan).not.toHaveBeenCalled();
});
it('discards old source responses after A to B to A and clears previous launch fields', async () => {
  let resolve!: (value: ApiResult<ConnectionPlan>) => void;
  vi.mocked(onboardingApi.choices).mockImplementationOnce(() => new Promise(done => { resolve = done; }));
  mount(); fireEvent.click(screen.getByRole('radio', { name: 'SDK startup injection' })); fill('Actual target module', 'old.tasks');
  fireEvent.click(screen.getByRole('button', { name: 'Load current sources and Workers (read only)' }));
  await waitFor(() => expect(onboardingApi.choices).toHaveBeenCalledTimes(1)); const signal = vi.mocked(onboardingApi.choices).mock.calls[0][1];
  await act(async () => { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 }); });
  await act(async () => { useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 3 }); resolve(result(plan('python-startup'))); });
  expect(signal.aborted).toBe(true); fireEvent.click(screen.getByRole('radio', { name: 'SDK startup injection' }));
  expect(screen.getByRole('textbox', { name: 'Actual target module' })).toHaveValue('');
  expect(screen.queryByText('Actual bound source')).not.toBeInTheDocument(); expect(onboardingApi.plan).not.toHaveBeenCalled();
});
it('an edited draft discards a late plan and its credential-environment and endpoint output', async () => {
  let resolve!: (value: ApiResult<ConnectionPlan>) => void;
  vi.mocked(onboardingApi.plan).mockImplementationOnce(() => new Promise(done => { resolve = done; })); mount();
  fireEvent.click(screen.getByRole('button', { name: 'Generate read-only connection plan' }));
  await waitFor(() => expect(onboardingApi.plan).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole('radio', { name: 'SDK startup injection' }));
  await act(async () => { resolve(result(plan('collector', { keyEnv: 'AGF_AGENT_TOKEN', endpoint: 'https://old.example.test' }))); });
  expect(screen.queryByText('https://old.example.test')).not.toBeInTheDocument(); expect(screen.queryByText('AGF_AGENT_TOKEN')).not.toBeInTheDocument();
});

it.each(['sender', 'callee'] as const)('requires explicit multi-Team %s selection without a default or runnable plan', async role => {
  const multi = { ...source, workers: [
    { name: 'Actual Worker', teams: role === 'sender' ? ['Sender One', 'Sender Two'] : ['Only Sender'] },
    { name: 'Other Worker', teams: ['Callee One', 'Callee Two'] },
  ] };
  vi.mocked(onboardingApi.choices).mockResolvedValue(result(plan('python-startup', { sdkSources: [multi] })));
  mount(); fireEvent.click(screen.getByRole('radio', { name: 'SDK startup injection' }));
  fireEvent.click(screen.getByRole('button', { name: 'Load current sources and Workers (read only)' }));
  await waitFor(() => expect(onboardingApi.choices).toHaveBeenCalledTimes(1));
  await select('Current audit source', `Actual bound source · Mock · ${source.sourceId}`);
  await select('Worker', 'Actual Worker');
  if (role === 'callee') {
    expect(screen.getByRole('button', { name: 'Generate read-only connection plan' })).toBeEnabled();
    await select('Event boundary', 'Worker call'); await select('Callee Worker', 'Other Worker');
  }
  const label = role === 'sender' ? 'Team' : 'Callee Team';
  expect(screen.getByRole('combobox', { name: label })).toHaveAttribute('aria-required', 'true');
  expect(screen.getByText('A selected Worker belongs to multiple Teams. Explicitly select its inventoried Team; none is selected automatically.')).toBeInTheDocument();
  const generate = screen.getByRole('button', { name: 'Generate read-only connection plan' });
  expect(generate).toBeDisabled(); fireEvent.click(generate); expect(onboardingApi.plan).not.toHaveBeenCalled();
  expect(screen.queryByText('Template generated; business deployment unverified')).not.toBeInTheDocument();
  const team = role === 'sender' ? 'Sender Two' : 'Callee Two'; await select(label, team);
  expect(generate).toBeEnabled(); fireEvent.click(generate);
  await waitFor(() => expect(onboardingApi.plan).toHaveBeenCalledTimes(1));
  const sent = vi.mocked(onboardingApi.plan).mock.calls[0][0].sdk;
  expect(sent?.[role === 'sender' ? 'team' : 'callee_team']).toBe(team);
  if (role === 'callee') expect(sent?.team).toBeNull();
});
