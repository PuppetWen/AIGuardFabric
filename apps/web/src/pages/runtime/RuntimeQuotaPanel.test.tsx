import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { message } from 'antd';
import { afterEach, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import { RuntimeQuotaPanel } from './RuntimeQuotaPanel';

const agent = '12345678-1234-4234-9234-123456789abc';
const definition = { id: 'quota-one', name: 'Worker token day', scope: 'agent', dimension: 'tokens',
  window: 'day', limit: 100, soft_threshold: 80, on_exceed: 'deny', enabled: true, version: 3, target_id: agent };
const clients: QueryClient[] = [];

async function mount(path = '/runtime') {
  await i18n.changeLanguage('en-US');
  vi.spyOn(message, 'success').mockImplementation(() => undefined as never);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  await act(async () => {
    render(<MemoryRouter initialEntries={[path]}><QueryClientProvider client={client}><RuntimeQuotaPanel /></QueryClientProvider></MemoryRouter>);
  });
}

afterEach(async () => {
  cleanup(); clients.splice(0).forEach(client => client.clear()); vi.unstubAllGlobals(); vi.restoreAllMocks();
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});

it('lets a read-only member inspect current versions without creating or editing quota rules', async () => {
  const request = vi.fn(async (url: string, options?: RequestInit) => {
    expect(options?.method).toBe('GET');
    const path = new URL(String(url), 'http://localhost').pathname;
    if (path === '/api/v1/auth/me') return Response.json({ access: { 'quotas:read': true, 'quotas:write': false }, roles: ['viewer'], superadmin: false });
    if (path === '/api/v1/quotas') return Response.json({ items: [{ quota: definition, used: 25, remaining: 75 }], total: 1, page: 1, page_size: 8, has_more: false });
    throw new Error(`Unexpected request: ${path}`);
  });
  vi.stubGlobal('fetch', request);
  await mount(`/runtime?quota_target=${agent}#quota-rules`);
  expect(await screen.findByText('Worker token day · v3')).toBeInTheDocument();
  expect(screen.getByText('25 / 100')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Create quota' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Save quota' })).not.toBeInTheDocument();
  expect(request.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true);
});

it('retains a conflicting draft and submits the newest version only after a confirmed reload', async () => {
  let current = { ...definition };
  let writes = 0;
  const request = vi.fn(async (url: string, options?: RequestInit) => {
    const path = new URL(String(url), 'http://localhost').pathname;
    if (path === '/api/v1/auth/me') return Response.json({ access: { 'quotas:read': true, 'quotas:write': true }, roles: ['tenant-admin'], superadmin: false });
    if (path !== '/api/v1/quotas') throw new Error(`Unexpected request: ${path}`);
    if (options?.method === 'POST') {
      writes += 1;
      const body = JSON.parse(String(options.body));
      if (writes === 1) {
        expect(body).toMatchObject({ expected_version: 3, limit: 125, target_id: agent });
        current = { ...current, limit: 150, version: 4 };
        return Response.json({ detail: 'Quota changed by another administrator' }, { status: 409 });
      }
      expect(body).toMatchObject({ expected_version: 4, limit: 200, target_id: agent });
      current = { ...current, limit: 200, version: 5 };
      return Response.json({ quota: current });
    }
    return Response.json({ items: [{ quota: current, used: 25, remaining: current.limit - 25 }], total: 1, page: 1, page_size: 8, has_more: false });
  });
  vi.stubGlobal('fetch', request);
  await mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
  const limit = screen.getByLabelText('Limit (0 sets no local limit)');
  fireEvent.change(limit, { target: { value: '125' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save quota' }));
  await screen.findByText(/Quota changed by another administrator/);
  expect(limit).toHaveValue('125');
  expect(screen.getByRole('button', { name: 'Save quota' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Save quota' }));
  expect(writes).toBe(1);
  fireEvent.click(screen.getByRole('button', { name: 'Load latest rule' }));
  fireEvent.click(await screen.findByRole('button', { name: 'OK' }));
  await waitFor(() => expect(screen.getByLabelText('Limit (0 sets no local limit)')).toHaveValue('150'));
  // AntD keeps its loading icon during exit motion; the action remains accessible and enabled.
  const nextSave = await screen.findByRole('button', { name: /Save quota$/ });
  await waitFor(() => {
    expect(nextSave).toBeEnabled();
    expect(nextSave).not.toHaveClass('ant-btn-loading');
  });
  fireEvent.change(screen.getByLabelText('Limit (0 sets no local limit)'), { target: { value: '200' } });
  fireEvent.click(nextSave);
  await screen.findByText('Worker token day · v5');
  expect(writes).toBe(2);
});

it('prefills a Worker target but requires its limit and a user click, and ignores duplicate clicks while saving', async () => {
  let release: () => void = () => { throw new Error('No pending save'); };
  const request = vi.fn(async (url: string, options?: RequestInit) => {
    const path = new URL(String(url), 'http://localhost').pathname;
    if (path === '/api/v1/auth/me') return Response.json({ access: { 'quotas:read': true, 'quotas:write': true }, roles: ['tenant-admin'], superadmin: false });
    if (path !== '/api/v1/quotas') throw new Error(`Unexpected request: ${path}`);
    if (options?.method === 'POST') {
      expect(JSON.parse(String(options.body))).toMatchObject({ name: 'new-worker-limit', expected_version: 0,
        scope: 'agent', dimension: 'tokens', window: 'day', action: 'deny', target_id: agent, limit: 1000 });
      await new Promise<void>(resolve => { release = resolve; });
      return Response.json({ quota: { ...definition, name: 'new-worker-limit', version: 1, limit: 1000, soft_threshold: 800 } });
    }
    return Response.json({ items: [], total: 0, page: 1, page_size: 8, has_more: false });
  });
  vi.stubGlobal('fetch', request);
  await mount(`/runtime?quota_target=${agent}#quota-rules`);
  const save = await screen.findByRole('button', { name: 'Save quota' });
  expect(screen.getByLabelText('Agent asset ID (empty applies to each Agent)')).toHaveValue(agent);
  expect(request.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  fireEvent.change(screen.getByLabelText('Quota name'), { target: { value: 'new-worker-limit' } });
  await act(async () => { fireEvent.click(save); });
  expect(request.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  fireEvent.change(screen.getByLabelText('Limit (0 sets no local limit)'), { target: { value: '1000' } });
  fireEvent.click(save); fireEvent.click(save);
  await waitFor(() => expect(request.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1));
  expect(screen.getByLabelText('Quota name')).toBeDisabled();
  expect(screen.getByLabelText('Limit (0 sets no local limit)')).toBeDisabled();
  await act(async () => { release(); });
  await waitFor(() => expect(save).not.toHaveClass('ant-btn-loading'));
});
