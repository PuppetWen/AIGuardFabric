import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cloudApi, type CloudConfig } from '@/api/cloud';
import { integrationsApi, type IntegrationConfig, type IntegrationRun } from '@/api/integrations';
import i18n from '@/locales/i18n';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import CloudOperations from '../alicloud/CloudOperations';
import IntegrationOperations from './IntegrationOperations';

const rights = new Set(['alicloud:write', 'integrations:write']);
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: () => ({ has: (permission: string) => rights.has(permission) }) }));
type Kind = 'cloud' | 'integration';
const kinds: Kind[] = ['cloud', 'integration'];
const original = useAuthStore.getState();
const caches: QueryClient[] = [];
const result = <T,>(data: T) => ({ data, meta: { source: 'live' as const, elapsedMs: 1, at: Date.now() } });
const cloud: CloudConfig = { name: 'cms', displayName: 'CMS', enabled: false, mock: false, environmentMock: false,
  version: 99, endpoint: 'https://cloud.example.test', settings: {}, secretKeys: [], operations: [
    { action: 'InspectFixture', version: '1', method: 'GET', path: '/', read_only: true, parameters: [] },
  ] };
const integration: IntegrationConfig = { name: 'webhook', enabled: false, mock: false, environmentMock: false,
  version: 99, settingsJson: '{}', secretKeys: [], probe: null,
  metadata: { requiredSecrets: [], optionalSecrets: [], endpointKey: null, degradation: '', semantics: {} } };
const backend = (kind: Kind) => kind === 'cloud' ? cloudApi : integrationsApi;
const name = (kind: Kind) => kind === 'cloud' ? cloud.name : integration.name;
function receipt(kind: Kind, overrides: Partial<IntegrationRun> = {}): IntegrationRun {
  return { id: 'owned-run', requestId: 'original-request', adapter: name(kind), operation: 'InspectFixture',
    configurationVersion: 7, actor: 'admin', startedAt: '2026-10-01T00:00:00Z', finishedAt: null,
    status: 'uncertain', mocked: false, completionState: 'pending_audit', providerStatus: 'succeeded',
    receipt: { RequestId: 'retained-provider-id' }, ...overrides };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(accept => { resolve = accept; });
  return { promise, resolve };
}
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  rights.clear(); rights.add('alicloud:write'); rights.add('integrations:write');
  useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 1 });
});
afterEach(async () => {
  cleanup(); caches.forEach(cache => cache.clear()); caches.length = 0;
  vi.restoreAllMocks(); useAuthStore.setState(original);
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});
function mount(kind: Kind) {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } }); caches.push(cache);
  return render(<QueryClientProvider client={cache}>
    {kind === 'cloud' ? <CloudOperations snapshot={cloud} /> : <IntegrationOperations snapshot={integration} />}
  </QueryClientProvider>);
}
async function setup(kind: Kind, value = receipt(kind)) {
  const api = backend(kind);
  const { receipt: _receipt, ...row } = value;
  const history = vi.spyOn(api, 'history').mockResolvedValue(result({ items: [row] }));
  const read = vi.spyOn(api, 'receipt').mockResolvedValue(result(value));
  const recover = vi.spyOn(api, 'recover');
  const execute = vi.spyOn(api, 'execute');
  mount(kind);
  fireEvent.click(await screen.findByRole('button', { name: 'View' }));
  await screen.findByText('Original configuration version');
  await waitFor(() => expect(screen.getByRole('button', { name: 'Read receipt again' })).toBeEnabled());
  return { history, read, recover, execute };
}

describe('explicit local receipt recovery', () => {
  it.each(kinds)('reads %s pending receipts without a write and recovers an old disabled configuration only on intent', async kind => {
    const { read, recover, execute } = await setup(kind);
    const pending = deferred<ReturnType<typeof result<IntegrationRun>>>();
    recover.mockReturnValue(pending.promise);
    expect(screen.getByText('Local audit pending · pending_audit')).toBeInTheDocument();
    expect(screen.getByText(/^succeeded · local publication/)).toBeInTheDocument();
    expect(screen.queryByText(/^(InspectFixture: succeeded|Live · succeeded)$/)).toBeNull();
    expect(screen.getByText(kind === 'cloud' ? 'InspectFixture: uncertain' : 'Live · uncertain').closest('.ant-alert')).toHaveClass('ant-alert-warning');
    expect(recover).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Read receipt again' }));
    await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
    const button = screen.getByRole('button', { name: 'Recover local receipt and audit' });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button); fireEvent.click(button);
    expect(recover).toHaveBeenCalledOnce();
    expect(recover).toHaveBeenCalledWith(name(kind), 'owned-run');
    expect(button).toBeDisabled();
    await act(async () => pending.resolve(result(receipt(kind, { status: 'succeeded', completionState: 'complete',
      providerStatus: undefined, finishedAt: '2026-10-01T00:01:00Z' }))));
    await screen.findByText('Local receipt and audit complete · complete');
    expect(screen.queryByRole('button', { name: 'Recover local receipt and audit' })).toBeNull();
    expect(execute).not.toHaveBeenCalled();
    expect(read.mock.calls.every(call => call[0] === name(kind) && call[1] === 'owned-run')).toBe(true);
  });

  it.each(kinds)('keeps the %s retained receipt after local audit failure and permits only another explicit recovery', async kind => {
    const { recover, execute } = await setup(kind);
    recover.mockRejectedValueOnce(new Error('Local audit unavailable')).mockResolvedValueOnce(result(receipt(kind, {
      status: 'succeeded', completionState: 'complete', providerStatus: undefined,
    })));
    fireEvent.click(screen.getByRole('button', { name: 'Recover local receipt and audit' }));
    await screen.findByText('Error: Local audit unavailable');
    expect(screen.getByText('Local audit pending · pending_audit')).toBeInTheDocument();
    expect(screen.getByText(/retained-provider-id/)).toBeInTheDocument();
    expect(recover).toHaveBeenCalledOnce(); expect(execute).not.toHaveBeenCalled();
    const button = screen.getByRole('button', { name: 'Recover local receipt and audit' });
    await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button);
    await screen.findByText('Local receipt and audit complete · complete');
    expect(recover).toHaveBeenCalledTimes(2);
  });

  it.each(kinds)('does not permit %s local recovery without the corresponding write capability', async kind => {
    rights.clear();
    rights.add(kind === 'cloud' ? 'alicloud:read' : 'integrations:read');
    const api = backend(kind);
    vi.spyOn(api, 'history').mockResolvedValue(result({ items: [receipt(kind, { receipt: undefined })] }));
    const read = vi.spyOn(api, 'receipt'); const recover = vi.spyOn(api, 'recover');
    mount(kind);
    const button = await screen.findByRole('button', { name: 'View' });
    expect(button).toBeDisabled(); fireEvent.click(button);
    expect(screen.getByText(`Receipt details and local recovery require ${kind === 'cloud' ? 'alicloud:write' : 'integrations:write'} in the current tenant. History metadata remains read only.`)).toBeInTheDocument();
    expect(screen.getByText('pending_audit')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Recover local receipt and audit' })).toBeNull();
    expect(read).not.toHaveBeenCalled(); expect(recover).not.toHaveBeenCalled();
  });

  it.each(kinds)('keeps a complete %s uncertain outcome uncertain and does not offer write replay', async kind => {
    const { recover, execute } = await setup(kind, receipt(kind, { completionState: 'complete', providerStatus: undefined }));
    await screen.findByText(/Local publication is complete, but the external outcome remains uncertain/);
    expect(screen.queryByText(/^(InspectFixture: succeeded|Live · succeeded)$/)).toBeNull();
    expect(screen.queryByRole('button', { name: 'Recover local receipt and audit' })).toBeNull();
    expect(recover).not.toHaveBeenCalled(); expect(execute).not.toHaveBeenCalled();
  });

  it.each(kinds)('keeps %s running receipts read only when no retained completion exists', async kind => {
    const { recover } = await setup(kind, receipt(kind, { status: 'started', completionState: 'running', receipt: undefined, providerStatus: undefined }));
    await screen.findByText(/No known retained receipt is available to recover/);
    expect(screen.queryByRole('button', { name: 'Recover local receipt and audit' })).toBeNull();
    expect(recover).not.toHaveBeenCalled();
  });

  it.each(kinds)('does not claim %s local completion when a legacy success has no completion metadata', async kind => {
    const { recover } = await setup(kind, receipt(kind, { status: 'succeeded', completionState: undefined, providerStatus: undefined }));
    await screen.findByText('Completion stage unavailable');
    expect(screen.getByText(kind === 'cloud' ? 'InspectFixture: succeeded' : 'Live · succeeded').closest('.ant-alert')).toHaveClass('ant-alert-warning');
    expect(screen.queryByRole('button', { name: 'Recover local receipt and audit' })).toBeNull();
    expect(recover).not.toHaveBeenCalled();
  });

  it.each(kinds)('discards a %s receipt GET arriving after a tenant switch', async kind => {
    const { read, recover } = await setup(kind);
    const late = deferred<ReturnType<typeof result<IntegrationRun>>>();
    read.mockReturnValueOnce(late.promise);
    fireEvent.click(screen.getByRole('button', { name: 'Read receipt again' }));
    await act(async () => useAuthStore.getState().setTenant({ id: 'tenant-two', slug: 'two' } as Tenant));
    await act(async () => late.resolve(result(receipt(kind, { requestId: 'late-private-request' }))));
    expect(screen.queryByText('late-private-request')).toBeNull();
    expect(screen.queryByText('original-request')).toBeNull();
    expect(recover).not.toHaveBeenCalled();
  });

  it.each(kinds)('discards a %s recovery POST arriving after a new sign-in', async kind => {
    const { recover } = await setup(kind);
    const late = deferred<ReturnType<typeof result<IntegrationRun>>>();
    recover.mockReturnValueOnce(late.promise);
    fireEvent.click(screen.getByRole('button', { name: 'Recover local receipt and audit' }));
    await act(async () => useAuthStore.setState({ sessionGeneration: 2 }));
    await act(async () => late.resolve(result(receipt(kind, { requestId: 'late-private-request', status: 'succeeded', completionState: 'complete' }))));
    expect(screen.queryByText('late-private-request')).toBeNull();
    expect(screen.queryByText('original-request')).toBeNull();
    expect(screen.queryByText('Local receipt and audit complete · complete')).toBeNull();
  });

  it.each(kinds)('does not replace a newer %s history refresh with an older initial response', async kind => {
    const initial = deferred<ReturnType<typeof result<{ items: IntegrationRun[] }>>>();
    const history = vi.spyOn(backend(kind), 'history').mockReturnValueOnce(initial.promise)
      .mockResolvedValue(result({ items: [receipt(kind, { operation: 'Current history operation' })] }));
    mount(kind);
    fireEvent.click(screen.getByRole('button', { name: 'Refresh history' }));
    await screen.findByText('Current history operation');
    await act(async () => initial.resolve(result({ items: [receipt(kind, { operation: 'Outdated history operation' })] })));
    expect(screen.queryByText('Outdated history operation')).toBeNull();
    expect(screen.getByText('Current history operation')).toBeInTheDocument();
    expect(history).toHaveBeenCalledTimes(2);
  });

  it('shows the Chinese recovery guide and explains pending classification without calling recover', async () => {
    await i18n.changeLanguage('zh-CN');
    vi.spyOn(integrationsApi, 'history').mockResolvedValue(result({ items: [] }));
    const recover = vi.spyOn(integrationsApi, 'recover');
    mount('integration');
    fireEvent.click(screen.getByText('回执状态与本地恢复指南'));
    await screen.findByText(/即使 provider_status 是 succeeded，页面结果仍为 uncertain/);
    await screen.findByText(/停用或修改连接后仍可读取和恢复旧回执/);
    expect(recover).not.toHaveBeenCalled();
  });
});
