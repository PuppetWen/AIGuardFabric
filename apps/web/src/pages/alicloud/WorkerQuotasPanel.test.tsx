import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { agentTeamsQuotasApi } from '@/api/agentTeamsQuotas';
import { useAuthStore } from '@/stores/authStore';
import type { WorkerQuotaBinding, WorkerQuotaObserveResult, WorkerQuotas } from '@/types/agentTeamsQuotas';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import { quotaFixture, quotasFixture } from './workerQuotaFixtures';
import WorkerQuotasPanel from './WorkerQuotasPanel';

const rights = new Set<string>();
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: () => ({ has: (permission: string) => rights.has(permission), isLoading: false, error: null }) }));
const meta = { source: 'live' as const, elapsedMs: 1, at: Date.now() };
const originalAuth = useAuthStore.getState();
const caches: QueryClient[] = [];
let data: WorkerQuotas;
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  rights.clear();
  ['alicloud:read', 'quotas:read', 'alicloud:write', 'quotas:write'].forEach(right => rights.add(right));
  useAuthStore.setState({ tenant: { id: 'tenant-one' } as Tenant, sessionGeneration: 1 });
  data = quotasFixture();
  vi.spyOn(agentTeamsQuotasApi, 'list').mockImplementation(async () => ({ data, meta }));
  vi.spyOn(agentTeamsQuotasApi, 'bind').mockImplementation(async (_assetId, request) => {
    const binding: WorkerQuotaBinding = { ...data.items[0], version: 4, enabled: request.enabled,
      state: request.enabled ? 'unverified' : 'disabled', observation: null };
    data = { ...data, items: [binding] };
    return { data: binding, meta };
  });
  vi.spyOn(agentTeamsQuotasApi, 'observe').mockImplementation(async () => {
    const binding = { ...data.items[0], observation: { ...data.items[0].observation!, id: 'preview-new',
      observedAt: new Date().toISOString(), previewUsable: true } };
    data = { ...data, items: [binding] };
    return { data: { binding, observation: binding.observation }, meta };
  });
  vi.spyOn(agentTeamsQuotasApi, 'sync').mockImplementation(async (_assetId, request) => {
    const binding: WorkerQuotaBinding = { ...data.items[0], state: 'in-sync',
      observation: { ...data.items[0].observation!, usageLimit: quotaFixture.limit, previewUsable: false },
      lastOperation: { id: 'operation-one', requestId: request.request_id, status: 'verified',
        startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), mocked: data.mocked === true, changed: true, error: null } };
    data = { ...data, items: [binding] };
    return { data: { binding, operation: binding.lastOperation! }, meta };
  });
});
afterEach(async () => {
  caches.forEach(cache => cache.clear()); caches.length = 0;
  vi.restoreAllMocks(); useAuthStore.setState(originalAuth);
  await i18n.changeLanguage('zh-CN');
});
function mount() {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  caches.push(cache);
  return render(<QueryClientProvider client={cache}><MemoryRouter><WorkerQuotasPanel /></MemoryRouter></QueryClientProvider>);
}
async function readCloud() {
  fireEvent.click(await screen.findByRole('button', { name: 'Read cloud' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Confirm read' }));
  await screen.findByText('Cloud read completed. Review the observation and platform target.');
}
async function confirmSync() {
  fireEvent.click(await screen.findByRole('button', { name: 'Review difference and sync' }));
  const confirm = await screen.findByRole('button', { name: 'Confirm write and readback' });
  expect(confirm).toBeDisabled();
  expect(agentTeamsQuotasApi.sync).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('checkbox', { name: 'I reviewed the Worker and difference and confirm the write above.' }));
  expect(confirm).toBeEnabled();
  fireEvent.click(confirm);
}

describe('Worker quota onboarding and explicit cloud writes', () => {
  it('displays configuration differences and provider usage without inventing a shared counter', async () => {
    mount();
    await screen.findByText('Difference observed');
    expect(screen.getByText('500')).toBeInTheDocument();
    expect(screen.getAllByText('Unknown').length).toBeGreaterThanOrEqual(3);
    expect(screen.queryByText('No')).not.toBeInTheDocument();
    expect(screen.getByText('Platform and cloud usage are independent')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open quota rules in Runtime protection' }))
      .toHaveAttribute('href', '/runtime?quota_target=asset-one#quota-rules');
    expect(agentTeamsQuotasApi.observe).not.toHaveBeenCalled();
    expect(agentTeamsQuotasApi.sync).not.toHaveBeenCalled();
  });

  it('does not fetch without both read permissions and separates observe from double write access', async () => {
    rights.delete('quotas:read');
    const closed = mount();
    await screen.findByText('Viewing Worker quotas requires alicloud:read and quotas:read.');
    expect(agentTeamsQuotasApi.list).not.toHaveBeenCalled(); closed.unmount();
    rights.add('quotas:read'); rights.delete('quotas:write'); data = { ...data, canWrite: false };
    mount();
    await screen.findByRole('button', { name: 'Read cloud' });
    expect(screen.queryByRole('button', { name: 'Save binding' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Review difference and sync' })).not.toBeInTheDocument();
  });

  it('saves versioned bindings without performing a cloud operation', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Save binding' }));
    await screen.findByText('Binding saved. Read cloud state and review the difference.');
    expect(agentTeamsQuotasApi.bind).toHaveBeenCalledWith('asset-one',
      { expected_version: 3, quota_id: 'quota-one', quota_version: 7, enabled: true });
    expect(agentTeamsQuotasApi.observe).not.toHaveBeenCalled(); expect(agentTeamsQuotasApi.sync).not.toHaveBeenCalled();
    await screen.findByText('Unverified');
  });

  it('requires an explicit cloud read and keeps all current versions in the request', async () => {
    mount(); await readCloud();
    expect(agentTeamsQuotasApi.observe).toHaveBeenCalledWith('asset-one',
      { request_id: expect.stringMatching(/^[0-9a-f-]{36}$/), expected_binding_version: 3,
        expected_quota_version: 7, configuration_version: 4, confirm_live: true });
    expect(agentTeamsQuotasApi.sync).not.toHaveBeenCalled();
  });

  it('requires reviewing a diff and checking confirmation before cloud write and readback', async () => {
    mount(); await confirmSync();
    await screen.findByText('Readback verified');
    expect(agentTeamsQuotasApi.sync).toHaveBeenCalledWith('asset-one',
      { request_id: expect.stringMatching(/^[0-9a-f-]{36}$/), expected_binding_version: 3,
        expected_quota_version: 7, configuration_version: 4, confirm_live: true, preview_id: 'preview-one' });
    expect(agentTeamsQuotasApi.sync).toHaveBeenCalledOnce();
    expect(screen.queryByRole('button', { name: 'Review difference and sync' })).not.toBeInTheDocument();
  });

  it('blocks expired and version changed previews while still allowing a new observation', async () => {
    data = { ...data, items: [{ ...data.items[0], observation: { ...data.items[0].observation!, observedAt: new Date(Date.now() - 301_000).toISOString() } }] };
    mount(); await screen.findByText('Reread before syncing');
    expect(screen.queryByRole('button', { name: 'Review difference and sync' })).not.toBeInTheDocument();
    await readCloud();
    await screen.findByRole('button', { name: 'Review difference and sync' });
    data = { ...data, quotas: [{ ...quotaFixture, version: 8, limit: 2000 }] };
    fireEvent.click(screen.getByRole('button', { name: 'Refresh quotas' }));
    await screen.findByText('3 / 8 / 4');
    expect(screen.queryByRole('button', { name: 'Review difference and sync' })).not.toBeInTheDocument();
  });

  it('retains unknown writes, forbids automatic resend and requires a new preview', async () => {
    vi.mocked(agentTeamsQuotasApi.sync).mockImplementation(async (_assetId, request) => {
      const binding: WorkerQuotaBinding = { ...data.items[0], observation: { ...data.items[0].observation!, previewUsable: false },
        lastOperation: { id: 'uncertain-receipt', requestId: request.request_id, status: 'uncertain',
          startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), mocked: false, changed: true, error: 'Cloud readback disconnected' } };
      data = { ...data, items: [binding] };
      return { data: { binding, operation: binding.lastOperation! }, meta };
    });
    mount(); await confirmSync();
    await screen.findByText('Result uncertain');
    expect(screen.getByText('uncertain-receipt')).toBeInTheDocument();
    expect(screen.getByText('Successful receipt received')).toBeInTheDocument();
    expect(agentTeamsQuotasApi.sync).toHaveBeenCalledOnce();
    expect(screen.queryByRole('button', { name: 'Review difference and sync' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh quotas' }));
    await waitFor(() => expect(agentTeamsQuotasApi.list).toHaveBeenCalledTimes(3));
    expect(agentTeamsQuotasApi.sync).toHaveBeenCalledOnce();
    await readCloud();
    await screen.findByRole('button', { name: 'Review difference and sync' });
  });

  it('keeps unsupported periods and stale or disabled bindings non-writable', async () => {
    data = { ...data, items: [{ ...data.items[0], observation: { ...data.items[0].observation!, periodType: 'month' } }] };
    mount();
    await screen.findByText('This cloud dimension or period cannot be synchronized. Only token/day is supported.');
    expect(screen.queryByRole('button', { name: 'Review difference and sync' })).not.toBeInTheDocument();
    data = { ...data, items: [{ ...data.items[0], state: 'stale' }] };
    fireEvent.click(screen.getByRole('button', { name: 'Refresh quotas' }));
    await screen.findByText('Invalid binding');
    expect(screen.queryByRole('button', { name: 'Read cloud' })).not.toBeInTheDocument();
    data = { ...data, items: [{ ...data.items[0], state: 'disabled', enabled: false }] };
    fireEvent.click(screen.getByRole('button', { name: 'Refresh quotas' }));
    await screen.findByText('Disabled');
    expect(screen.queryByRole('button', { name: 'Read cloud' })).not.toBeInTheDocument();
  });

  it('labels mock state and does not claim live confirmation for simulated reads', async () => {
    data = { ...data, mocked: true, items: [{ ...data.items[0], mocked: true,
      observation: { ...data.items[0].observation!, mocked: true } }] };
    mount(); await readCloud();
    expect(screen.getAllByText('Mock').length).toBeGreaterThanOrEqual(2);
    expect(agentTeamsQuotasApi.observe).toHaveBeenCalledWith('asset-one', expect.objectContaining({ confirm_live: false }));
  });

  it('links a persisted drift alert only when the viewer has alerts read access', async () => {
    data = { ...data, items: [{ ...data.items[0], driftAlertId: 'drift-alert-one' }] };
    rights.add('alerts:read');
    const allowed = mount();
    await screen.findByText('A quota drift alert has been recorded');
    expect(screen.getByRole('link', { name: 'View quota drift alert' })).toHaveAttribute('href', '/alerts?alert=drift-alert-one');
    allowed.unmount(); rights.delete('alerts:read');
    mount(); await screen.findByText('Viewing this alert requires alerts:read.');
    expect(screen.queryByRole('link', { name: 'View quota drift alert' })).not.toBeInTheDocument();
  });

  it('allows an explicit recovery read only after the server releases an expired lease', async () => {
    const operation = { id: 'interrupted-operation', requestId: 'old-request', status: 'started' as const,
      startedAt: new Date().toISOString(), finishedAt: null, mocked: false, changed: false, error: null };
    data = { ...data, items: [{ ...data.items[0], state: 'unverified', busy: true, canObserve: false,
      leaseExpiresAt: new Date(Date.now() + 120_000).toISOString(), lastOperation: operation,
      observation: { ...data.items[0].observation!, previewUsable: false } }] };
    mount();
    expect(await screen.findByRole('button', { name: 'Read cloud' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Save binding' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Review difference and sync' })).not.toBeInTheDocument();
    expect(agentTeamsQuotasApi.observe).not.toHaveBeenCalled();
    data = { ...data, items: [{ ...data.items[0], busy: false, canObserve: true,
      leaseExpiresAt: new Date(Date.now() - 1000).toISOString(), lastOperation: { ...operation, status: 'uncertain' } }] };
    fireEvent.click(screen.getByRole('button', { name: 'Refresh quotas' }));
    await screen.findByText('Result uncertain');
    expect(screen.getByRole('button', { name: 'Read cloud' })).toBeEnabled();
    expect(agentTeamsQuotasApi.observe).not.toHaveBeenCalled();
    expect(agentTeamsQuotasApi.sync).not.toHaveBeenCalled();
    await readCloud();
    await screen.findByRole('button', { name: 'Review difference and sync' });
    expect(agentTeamsQuotasApi.observe).toHaveBeenCalledOnce();
    expect(agentTeamsQuotasApi.sync).not.toHaveBeenCalled();
  });

  it('keeps old instance bindings visible and allows disabling after the quota is removed', async () => {
    data = { ...data, inventoryAvailable: false, cloudVersion: 0, mocked: null, workers: [], quotas: [],
      items: [{ ...data.items[0], state: 'stale', quotaVersion: null, quotaName: null, platformLimit: null }] };
    mount(); await screen.findByText('Invalid binding');
    expect(screen.getByRole('button', { name: 'Save binding' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Read cloud' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Disable binding' }));
    fireEvent.click(await screen.findByRole('button', { name: 'OK' }));
    await screen.findByText('Synchronization binding disabled. Cloud limits remain as configured.');
    expect(agentTeamsQuotasApi.bind).toHaveBeenCalledWith('asset-one',
      { expected_version: 3, quota_id: 'quota-one', quota_version: 0, enabled: false });
    expect(agentTeamsQuotasApi.sync).not.toHaveBeenCalled();
  });

  it('does not present a lost write receipt as proof that no write happened', async () => {
    data = { ...data, items: [{ ...data.items[0], state: 'unverified',
      observation: { ...data.items[0].observation!, previewUsable: false },
      lastOperation: { id: 'lost-write-receipt', requestId: 'request-lost', status: 'uncertain',
        startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), mocked: false,
        changed: false, error: 'UpdateWorker response unavailable' } }] };
    mount(); await screen.findByText('Result uncertain');
    expect(screen.getByText('Write receipt')).toBeInTheDocument();
    expect(screen.getByText('Unconfirmed')).toBeInTheDocument();
    expect(screen.queryByText('No')).not.toBeInTheDocument();
    expect(screen.queryByText('No write needed')).not.toBeInTheDocument();
    expect(agentTeamsQuotasApi.sync).not.toHaveBeenCalled();
  });

  it('reports no write needed only after matching readback verified the existing limit', async () => {
    data = { ...data, items: [{ ...data.items[0], state: 'in-sync',
      observation: { ...data.items[0].observation!, usageLimit: quotaFixture.limit, previewUsable: false },
      lastOperation: { id: 'unchanged-receipt', requestId: 'request-unchanged', status: 'verified',
        startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), mocked: false,
        changed: false, error: null } }] };
    mount(); await screen.findByText('Readback verified');
    expect(screen.getByText('No write needed')).toBeInTheDocument();
    expect(screen.queryByText('Unconfirmed')).not.toBeInTheDocument();
    expect(screen.queryByText('Successful receipt received')).not.toBeInTheDocument();
    expect(agentTeamsQuotasApi.sync).not.toHaveBeenCalled();
  });

  it('discards old tenant state and ignores an old in-flight read completion', async () => {
    let finish!: (response: { data: WorkerQuotaObserveResult; meta: typeof meta }) => void;
    vi.mocked(agentTeamsQuotasApi.observe).mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const oldBinding = data.items[0];
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Read cloud' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Confirm read' }));
    await waitFor(() => expect(agentTeamsQuotasApi.observe).toHaveBeenCalledOnce());
    data = { ...data, workers: [], items: [] };
    act(() => useAuthStore.setState({ tenant: { id: 'tenant-two' } as Tenant }));
    await screen.findByText('The complete inventory contains no bindable Worker.');
    await act(async () => { finish({ data: { binding: oldBinding, observation: oldBinding.observation! }, meta }); });
    expect(agentTeamsQuotasApi.list).toHaveBeenCalledTimes(2);
    expect(screen.queryByText('Cloud read completed. Review the observation and platform target.')).not.toBeInTheDocument();
    expect(screen.queryByText('Difference observed')).not.toBeInTheDocument();
  });

  it('shows backend failures and missing inventory without simulated quota success', async () => {
    vi.mocked(agentTeamsQuotasApi.list).mockRejectedValue(new Error('Worker backend unavailable'));
    const failed = mount(); await screen.findByText('Worker backend unavailable');
    expect(screen.queryByText('Difference observed')).not.toBeInTheDocument(); failed.unmount();
    vi.mocked(agentTeamsQuotasApi.list).mockResolvedValue({ data: { ...data, inventoryAvailable: false, workers: [], items: [] }, meta });
    mount(); await screen.findByText('Complete inventory for the current instance before binding Worker quotas.');
    expect(screen.getByRole('button', { name: 'Save binding' })).toBeDisabled();
    expect(agentTeamsQuotasApi.bind).not.toHaveBeenCalled();
  });
});
