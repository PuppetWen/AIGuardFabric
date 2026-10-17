import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import { CreateApiKeyModal } from './CreateApiKeyModal';

afterEach(() => vi.unstubAllGlobals());

it('can issue the minimal platform key required by the MCP client guide', async () => {
  await i18n.changeLanguage('zh-CN');
  const writes: Record<string, unknown>[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, options?: RequestInit) => {
    const path = new URL(String(url), 'http://localhost').pathname;
    if (path === '/api/v1/settings/api-keys' && options?.method === 'POST') {
      writes.push(JSON.parse(String(options.body)) as Record<string, unknown>);
      return Response.json({ plaintext: 'agf_test_fixture' }, { status: 201 });
    }
    if (path === '/api/v1/agents') return Response.json({ items: [], total: 0 });
    throw new Error(`Unexpected request: ${path}`);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}>
    <CreateApiKeyModal open onCancel={vi.fn()} onConfirm={vi.fn()} />
  </QueryClientProvider>);
  fireEvent.change(screen.getByRole('textbox', { name: '名称' }), { target: { value: 'MCP read client' } });
  const scopes = screen.getByRole('combobox', { name: '权限范围' });
  fireEvent.mouseDown(scopes);
  fireEvent.click(await screen.findByText('mcps:execute'));
  fireEvent.mouseDown(scopes);
  fireEvent.change(scopes, { target: { value: 'policies:read' } });
  fireEvent.click((await screen.findAllByText('policies:read')).at(-1)!);
  fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0]).toEqual(expect.objectContaining({ name: 'MCP read client',
    scopes: ['mcps:execute', 'policies:read'] }));
  expect(await screen.findByText('agf_test_fixture')).toBeInTheDocument();
  view.unmount(); client.clear();
});

it('prefills only supported ingest scopes and explains key creation in English', async () => {
  await i18n.changeLanguage('en-US');
  const writes: Record<string, unknown>[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, options?: RequestInit) => {
    const path = new URL(String(url), 'http://localhost').pathname;
    if (path === '/api/v1/settings/api-keys' && options?.method === 'POST') {
      writes.push(JSON.parse(String(options.body)) as Record<string, unknown>);
      return Response.json({ plaintext: 'agf_test_fixture' }, { status: 201 });
    }
    if (path === '/api/v1/agents') return Response.json({ items: [], total: 0 });
    throw new Error(`Unexpected request: ${path}`);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}>
    <CreateApiKeyModal open initialScopes={['sources:write', 'platform:admin', 'sources:write']}
      onCancel={vi.fn()} onConfirm={vi.fn()} />
  </QueryClientProvider>);
  expect(screen.getByText(/Grant only the scopes needed/)).toBeInTheDocument();
  expect(screen.getByText('sources:write')).toBeInTheDocument();
  fireEvent.change(screen.getByRole('textbox', { name: 'Name' }), { target: { value: 'Webhook client' } });
  fireEvent.click(screen.getByRole('button', { name: 'Create' }));
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0]).toEqual(expect.objectContaining({ name: 'Webhook client', scopes: ['sources:write'] }));
  view.unmount(); client.clear();
});

it('lets an administrator select the minimal Worker quota management scopes from the form', async () => {
  await i18n.changeLanguage('en-US');
  const writes: Record<string, unknown>[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, options?: RequestInit) => {
    const path = new URL(String(url), 'http://localhost').pathname;
    if (path === '/api/v1/settings/api-keys' && options?.method === 'POST') {
      writes.push(JSON.parse(String(options.body)) as Record<string, unknown>);
      return Response.json({ plaintext: 'agf_quota_fixture' }, { status: 201 });
    }
    if (path === '/api/v1/agents') return Response.json({ items: [], total: 0 });
    throw new Error(`Unexpected request: ${path}`);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}>
    <CreateApiKeyModal open onCancel={vi.fn()} onConfirm={vi.fn()} />
  </QueryClientProvider>);
  const expected = ['alicloud:read', 'alicloud:write', 'quotas:read', 'quotas:write'];
  const scopes = screen.getByRole('combobox', { name: 'Scopes' });
  for (const scope of expected) {
    fireEvent.mouseDown(scopes);
    fireEvent.change(scopes, { target: { value: scope } });
    fireEvent.click((await screen.findAllByText(scope)).at(-1)!);
  }
  fireEvent.change(screen.getByRole('textbox', { name: 'Name' }), { target: { value: 'Worker quota manager' } });
  fireEvent.click(screen.getByRole('button', { name: 'Create' }));
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0]).toEqual(expect.objectContaining({ scopes: expected }));
  expect(await screen.findByText('agf_quota_fixture')).toBeInTheDocument();
  view.unmount(); client.clear();
});
