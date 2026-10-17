import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import i18n from '@/locales/i18n';
import { HttpEndpointConsole } from './HttpEndpointConsole';

afterEach(() => vi.unstubAllGlobals());

it('saves, probes, and reloads a legacy SSE connection from the operator form', async () => {
  await i18n.changeLanguage('zh-CN');
  const writes: Record<string, unknown>[] = [];
  let saved: Record<string, unknown> | undefined;
  vi.stubGlobal('fetch', vi.fn(async (url: string, options?: RequestInit) => {
    const path = new URL(String(url), 'http://localhost').pathname;
    if (path === '/api/v1/mcp/endpoints' && options?.method === 'POST') {
      const body = JSON.parse(String(options.body)) as Record<string, unknown>;
      writes.push(body);
      saved = { id: 'legacy-one', version: 1, name: body.name, url: body.url,
        transport: body.transport, enabled: body.enabled, idle_timeout_secs: body.idle_timeout_secs,
        allowed_origins: body.allowed_origins, credential_configured: true };
      return Response.json(saved);
    }
    if (path === '/api/v1/mcp/endpoints/legacy-one/probe' && options?.method === 'POST') {
      expect(JSON.parse(String(options.body))).toEqual({ protocol: '2024-11-05' });
      return Response.json({ protocol: '2024-11-05', server: { name: 'legacy-mock' },
        tools: { tools: [{ name: 'read_only' }] }, session_closed: true });
    }
    if (path === '/api/v1/mcp/endpoints/legacy-one/usage') {
      return Response.json({ endpoint_id: 'legacy-one', items: [{ name: 'read_only', attempts: 1,
        succeeded: 1, failed: 0, unknown: 0, inflight: 0, latency_ms_total: 4 }] });
    }
    if (path === '/api/v1/mcp/endpoints/legacy-one/oauth') {
      return Response.json({ configuration: null, status: { connected: false, expires_at: null, refreshable: false } });
    }
    if (path === '/api/v1/mcp/endpoints' && (!options?.method || options.method === 'GET')) {
      return Response.json({ items: saved ? [saved] : [], can_write: true, can_execute: true });
    }
    throw new Error(`Unexpected request: ${path}`);
  }));

  const mount = () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const view = render(<MemoryRouter><QueryClientProvider client={client}>
      <HttpEndpointConsole />
    </QueryClientProvider></MemoryRouter>);
    return { view, client };
  };
  const first = mount();
  fireEvent.click(screen.getByRole('button', { name: 'HTTP 接入配置' }));
  const add = await screen.findByRole('button', { name: '新增 MCP 端点' });
  await waitFor(() => expect(add).toBeEnabled());
  fireEvent.click(add);
  fireEvent.change(screen.getByRole('textbox', { name: '名称' }), { target: { value: 'Legacy demo' } });
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '传输协议' }));
  fireEvent.click(await screen.findByText('HTTP + SSE (2024-11-05)'));
  fireEvent.change(screen.getByRole('textbox', { name: '上游 MCP URL' }),
    { target: { value: 'http://127.0.0.1:18912/sse' } });
  fireEvent.change(screen.getByLabelText('上游 Bearer token（留空保留已有凭据）'),
    { target: { value: 'fixture-token' } });
  fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }));
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0]).toEqual(expect.objectContaining({ name: 'Legacy demo',
    transport: 'legacy-sse', url: 'http://127.0.0.1:18912/sse', bearer_token: 'fixture-token' }));
  expect(await screen.findByText('2024-11-05 HTTP+SSE')).toBeVisible();
  expect(await screen.findByText('此端点的工具用量')).toBeVisible();
  expect(await screen.findByText('read_only')).toBeVisible();
  expect(screen.getByRole('link', { name: '前往创建平台 API Key' })).toHaveAttribute('href',
    '/settings?tab=apiKeys&createKey=1&scopes=mcps%3Aexecute%2Cpolicies%3Aread');
  fireEvent.click(screen.getByRole('button', { name: '检测连接与工具列表' }));
  expect(await screen.findByText('握手与工具列表获取成功')).toBeVisible();
  first.view.unmount(); first.client.clear();

  const second = mount();
  fireEvent.click(screen.getByRole('button', { name: 'HTTP 接入配置' }));
  expect(await screen.findByText('Legacy demo')).toBeVisible();
  expect(screen.getByText('SSE 2024')).toBeVisible();
  expect(screen.getByText(/1 · 已配置/)).toBeVisible();
  second.view.unmount(); second.client.clear();
}, 15000);
