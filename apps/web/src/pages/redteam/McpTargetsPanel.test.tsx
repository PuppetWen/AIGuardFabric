import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import { McpTargetsPanel, type McpTargetProfile } from './McpTargetsPanel';

const profiles: McpTargetProfile[] = ['query-target', 'detail-target'].map((id, index) => ({
  id, assetId: `asset-${index}`, name: index === 0 ? 'Query fixture' : 'Detail fixture',
  url: `https://mcp-${index}.example/mcp`, toolName: 'safe_query', argumentName: 'query',
  enabled: true, version: 1, credentialConfigured: false, canaryConfigured: true,
}));

afterEach(async () => {
  cleanup();
  vi.unstubAllGlobals();
  await i18n.changeLanguage('zh-CN');
});

it('lets a read-only user inspect and refresh the selected target usage without configuration writes', async () => {
  await i18n.changeLanguage('en-US');
  let refreshed = false;
  const request = vi.fn(async (url: string, options?: RequestInit) => {
    expect(options?.method).toBe('GET');
    const path = new URL(String(url), 'http://localhost').pathname;
    const data = path === '/api/v1/redteam/mcp-targets' ? { items: profiles }
      : path === '/api/v1/redteam/mcp-targets/query-target/usage' ? { items: [{
        name: 'safe_query', attempts: 6, succeeded: 2, failed: 1, unknown: 2, inflight: 1,
        latency_ms_total: 300,
      }] } : path === '/api/v1/redteam/mcp-targets/detail-target/usage' ? { items: [{
        name: 'safe_detail', attempts: refreshed ? 2 : 1, succeeded: refreshed ? 2 : 1,
        failed: 0, unknown: 0, inflight: 0, latency_ms_total: refreshed ? 80 : 40,
      }] } : undefined;
    if (!data) throw new Error(`Unexpected request: ${path}`);
    return Response.json(data);
  });
  vi.stubGlobal('fetch', request);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><McpTargetsPanel canConfigure={false} /></QueryClientProvider>);

  const queryProfile = (await screen.findByText('Query fixture')).closest('tr')!;
  expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Connect MCP target' })).not.toBeInTheDocument();
  fireEvent.click(within(queryProfile).getByRole('button', { name: 'Usage' }));
  expect(await screen.findByRole('heading', { name: 'Red-team target tool usage' })).toBeInTheDocument();
  const queryRow = await screen.findByRole('row', { name: /safe_query 6 2 1 2 1 100 ms/ });
  expect(within(queryRow).getAllByRole('cell').map(cell => cell.textContent))
    .toEqual(['safe_query', '6', '2', '1', '2', '1', '100 ms']);
  expect(request.mock.calls.some(([url]) => String(url).endsWith('/query-target/usage'))).toBe(true);

  const detailProfile = screen.getByText('Detail fixture').closest('tr')!;
  fireEvent.click(within(detailProfile).getByRole('button', { name: 'Usage' }));
  await screen.findByRole('row', { name: /safe_detail 1 1 0 0 0 40 ms/ });
  expect(screen.queryByRole('row', { name: /safe_query 6 2/ })).not.toBeInTheDocument();
  refreshed = true;
  await waitFor(() => expect(screen.getByRole('button', { name: /Refresh usage/ })).not.toHaveClass('ant-btn-loading'));
  fireEvent.click(screen.getByRole('button', { name: /Refresh usage/ }));
  await screen.findByRole('row', { name: /safe_detail 2 2 0 0 0 40 ms/ });
  expect(request.mock.calls.filter(([url]) => String(url).endsWith('/detail-target/usage'))).toHaveLength(2);

  fireEvent.click(screen.getByRole('button', { name: 'Close' }));
  await waitFor(() => expect(screen.queryByRole('heading', { name: 'Red-team target tool usage' })).not.toBeInTheDocument());
  expect(request.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true);
  expect(request.mock.calls.every(([url]) => !String(url).includes('/api/v1/mcp/endpoints/'))).toBe(true);
  client.clear();
});
