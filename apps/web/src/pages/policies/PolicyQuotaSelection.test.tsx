import { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ConfigProvider, message } from 'antd';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { api } from '@/api/client';
import { policiesApi } from '@/api/policies';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import PoliciesPage from '../PoliciesPage';
import { PolicyQuotaSelection } from './PolicyQuotaSelection';
import { policyFixture, policyResult } from './policyTestFixtures';

vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
const firstId = 'a12bc345-6789-4abc-8def-0123456789ab', disabledId = 'b12bc345-6789-4abc-8def-0123456789ab';
const oldId = 'c12bc345-6789-4abc-8def-0123456789ab', tenantId = 'd12bc345-6789-4abc-8def-0123456789ab';
const originalAuth = useAuthStore.getState(), caches: QueryClient[] = [];
let requests: ReturnType<typeof vi.fn>, rights: Set<string>;
const definition = (id = firstId, name = 'Current limit', enabled = true) => ({ id, name, scope: 'tenant', dimension: 'requests',
  window: 'minute', limit: 40, soft_threshold: 0, on_exceed: 'deny', enabled, version: 3 });
const page = (items = [definition()], current = 1, more = false) => Response.json({ items: items.map(quota => ({ quota, used: 0, remaining: 40 })),
  total: items.length + (more ? 1 : 0), page: current, page_size: 100, has_more: more });
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  useAuthStore.setState({ tenant: { id: tenantId, slug: 'one' } as Tenant, token: null, sessionGeneration: 1 });
  rights = new Set(['quotas:read', 'policies:read', 'policies:write']);
  vi.mocked(useSessionAccess).mockImplementation(() => ({ has: (permission: string) => rights.has(permission), isLoading: false }) as unknown as ReturnType<typeof useSessionAccess>);
  requests = vi.fn(async (url: string, options?: RequestInit) => {
    expect(options?.method).toBe('GET');
    const path = new URL(String(url), 'http://localhost');
    expect(path.pathname).toBe('/api/v1/quotas'); expect(path.searchParams.get('page_size')).toBe('100');
    return page([definition(), definition(disabledId, 'Disabled limit', false)]);
  });
  vi.stubGlobal('fetch', requests);
  vi.spyOn(message, 'success').mockImplementation(() => undefined as never);
});
afterEach(async () => {
  cleanup(); caches.splice(0).forEach(cache => cache.clear()); vi.unstubAllGlobals(); vi.restoreAllMocks();
  act(() => message.destroy()); useAuthStore.setState(originalAuth);
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});
function Controlled({ initial }: { initial?: string }) {
  const [value, setValue] = useState(initial);
  return <><PolicyQuotaSelection value={value} onChange={setValue} /><output aria-label="Policy quota draft">{value ?? ''}</output></>;
}
function Scoped({ initial }: { initial?: string }) {
  const tenant = useAuthStore(state => state.tenant), generation = useAuthStore(state => state.sessionGeneration);
  return <Controlled key={`${tenant?.id}:${tenant?.slug}:${generation}`} initial={generation === 1 ? initial : undefined} />;
}
function mount(initial?: string) {
  render(<ConfigProvider theme={{ token: { motion: false } }}><Scoped initial={initial} /></ConfigProvider>);
}
async function chooseFirst() {
  const input = screen.getByRole('combobox', { name: 'Select current tenant quota' });
  await waitFor(() => expect(input).toBeEnabled()); fireEvent.mouseDown(input);
  fireEvent.click(await screen.findByText(`${definition().name} · ${firstId} · v3 · tenant/requests/minute`));
}

it('never defaults to a quota and preserves actual disabled dependencies until the user explicitly chooses an enabled rule', async () => {
  mount(disabledId);
  await screen.findByText(/The linked quota is disabled/);
  expect(screen.getByLabelText('Current quota ID')).toHaveValue(disabledId);
  expect(screen.getByLabelText('Policy quota draft')).toHaveTextContent(disabledId);
  await chooseFirst();
  expect(screen.getByLabelText('Current quota ID')).toHaveValue(firstId);
  expect(screen.getByLabelText('Policy quota draft')).toHaveTextContent(firstId);
  expect(requests).toHaveBeenCalledTimes(1);
});

it('reports a deleted or unavailable existing ID without silently overwriting it', async () => {
  mount(oldId);
  await screen.findByText(/This ID was not returned by the current tenant list/);
  expect(screen.getByLabelText('Current quota ID')).toHaveValue(oldId);
  expect(screen.getByLabelText('Policy quota draft')).toHaveTextContent(oldId);
  expect(requests).toHaveBeenCalledTimes(1);
});

it('does not mistake an unloaded page for a deleted dependency and changes no draft while loading it', async () => {
  requests.mockImplementation(async (url: string) => new URL(url, 'http://localhost').searchParams.get('page') === '1'
    ? page([definition()], 1, true) : page([definition(oldId, 'Existing second-page limit')], 2));
  mount(oldId);
  await screen.findByRole('button', { name: 'Load more quotas' });
  expect(screen.getByText(/The existing ID is not verified in the loaded pages/)).toBeInTheDocument();
  expect(screen.queryByText(/may be deleted/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Load more quotas' }));
  await screen.findByText(`Existing second-page limit · ${oldId} · v3 · tenant/requests/minute`);
  expect(screen.getByLabelText('Policy quota draft')).toHaveTextContent(oldId);
  expect(requests).toHaveBeenCalledTimes(2);
});

it('keeps a failed query and its existing ID visible without presenting example choices', async () => {
  requests.mockResolvedValue(Response.json({ detail: 'Owned quota read failed' }, { status: 503 }));
  mount(oldId);
  await screen.findByText('The actual quota list could not be read; no examples are used and the draft is unchanged.');
  expect(screen.getByLabelText('Current quota ID')).toHaveValue(oldId);
  expect(screen.getByRole('combobox', { name: 'Select current tenant quota' })).toBeDisabled();
  expect(screen.queryByText(/Current limit ·/)).not.toBeInTheDocument();
  requests.mockImplementation(async () => page());
  fireEvent.click(screen.getByRole('button', { name: 'Refresh actual quota list' }));
  await screen.findByText(/This ID was not returned by the current tenant list/);
  expect(screen.getByLabelText('Policy quota draft')).toHaveTextContent(oldId);
  expect(requests).toHaveBeenCalledTimes(2);
});

it('does not request quota records without quotas:read and retains the existing draft ID', () => {
  rights.delete('quotas:read'); mount(oldId);
  expect(screen.getByText('Selecting a quota requires quotas:read; the current draft ID is unchanged.')).toBeInTheDocument();
  expect(screen.getByLabelText('Current quota ID')).toHaveValue(oldId);
  expect(requests).not.toHaveBeenCalled();
});

it.each(['tenant', 'session'] as const)('aborts the old %s request and never leaks its late choices or selection', async change => {
  let finish!: (response: Response) => void;
  requests.mockImplementationOnce(() => new Promise<Response>(resolve => { finish = resolve; }));
  mount(oldId); await waitFor(() => expect(requests).toHaveBeenCalledTimes(1));
  const oldSignal = requests.mock.calls[0][1]?.signal;
  requests.mockImplementation(async () => page([definition(disabledId, 'New scope limit')]));
  act(() => useAuthStore.setState({ sessionGeneration: 2, ...(change === 'tenant'
    ? { tenant: { id: firstId, slug: 'two' } as Tenant } : {}) }));
  await waitFor(() => expect(requests).toHaveBeenCalledTimes(2));
  expect(oldSignal?.aborted).toBe(true);
  await act(async () => { finish(page([definition(firstId, 'Old private choice')])); });
  expect(screen.queryByText(/Old private choice/)).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Current quota ID')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Policy quota draft')).toBeEmptyDOMElement();
  const input = screen.getByRole('combobox', { name: 'Select current tenant quota' });
  await waitFor(() => expect(input).toBeEnabled()); fireEvent.mouseDown(input);
  expect(await screen.findByText(`New scope limit · ${disabledId} · v3 · tenant/requests/minute`)).toBeInTheDocument();
});

it('submits only an explicitly selected actual UUID through PolicyEditor while retaining action, language and intercept points', async () => {
  const policy = policyFixture(4, { action: 'quota', code: 'true ? {"action":"quota"} : {}', quotaId: undefined });
  vi.spyOn(api, 'policies').mockResolvedValue(policyResult({ items: [policy], total: 1, page: 1, pageSize: 50 }));
  const save = vi.spyOn(policiesApi, 'save').mockResolvedValue(policyResult({ ...policy, quotaId: firstId, version: 5 }));
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } }); caches.push(cache);
  render(<ConfigProvider theme={{ token: { motion: false } }}><QueryClientProvider client={cache}>
    <MemoryRouter><PoliciesPage /></MemoryRouter>
  </QueryClientProvider></ConfigProvider>);
  fireEvent.click(await screen.findByText('Owned policy'));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Select current tenant quota' })).toBeEnabled());
  expect(screen.queryByLabelText('Current quota ID')).not.toBeInTheDocument(); expect(save).not.toHaveBeenCalled();
  await chooseFirst(); fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  expect(save).toHaveBeenCalledWith(expect.objectContaining({ quotaId: firstId, action: 'quota', codeLanguage: 'cel',
    code: policy.code, interceptPoints: ['mcp-proxy'] }), 4);
  expect(requests.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true);
});
