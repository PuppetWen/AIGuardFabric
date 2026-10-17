import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';

import i18n from '@/locales/i18n';
import RuntimePage from './RuntimePage';

const access = vi.hoisted(() => ({ canWrite: false }));
const writes = vi.hoisted(() => ({
  update: vi.fn(async () => undefined),
  remove: vi.fn(async () => undefined),
  refetch: vi.fn(async () => undefined),
}));
beforeEach(() => { access.canWrite = false; vi.clearAllMocks(); });
const events = vi.hoisted(() => [
  {
    id: 'tool-only', ts: '2026-09-26T00:00:00Z', point: 'mcp-proxy', agentName: 'Agent A',
    mcpName: null, toolName: 'query_docs', action: 'deny', policyName: 'test policy',
    reason: 'blocked', payloadDigest: 'test-hash', latencyMs: 0.025, severity: 'high',
  },
  {
    id: 'named-server', ts: '2026-09-26T00:00:01Z', point: 'mcp-proxy', agentName: 'Agent B',
    mcpName: 'docs-server', toolName: 'read_page', action: 'allow', policyName: '-',
    reason: 'allowed', payloadDigest: 'another-hash', latencyMs: 1.5, severity: 'info',
  },
]);

vi.mock('@/api/client', () => ({
  api: { updateBlacklist: writes.update, deleteBlacklist: writes.remove },
  summariseQuotas: () => ({ tenant: 0, agent: 0, session: 0 }),
  useApiQuery: (key: string) => ({
    data: { data: key === 'intercept-events' ? events : key === 'intercept-points' ? [{
      point: 'mcp-proxy', enabled: false, mode: 'bypass', health: 'unknown',
      throughputPerMin: 0, blocked24h: 0, p95LatencyMs: 0, version: '0.1', lastError: null,
    }] : key === 'blacklists' ? [{
      id: 'rule-one', version: 7, kind: 'command', pattern: 're:test', action: 'deny',
      scope: 'tenant', enabled: true, hits24h: 0, note: '', updatedAt: '2026-09-26T00:00:00Z',
    }] : [] },
    isLoading: false,
    error: null,
    refetch: writes.refetch,
  }),
}));
vi.mock('@/api/sessionAccess', () => ({
  useSessionAccess: () => ({ has: (permission: string) => permission === 'policies:write' && access.canWrite }),
}));
vi.mock('@/components/MiniChart', () => ({
  MiniChart: () => null,
  useChartTokens: () => ({ text: '#000', textStrong: '#000', grid: '#000', tooltipBg: '#fff', tooltipBorder: '#000' }),
}));
it('shows a tool name even when the audit event has no MCP server name', () => {
  render(<RuntimePage />);
  expect(screen.getByText('query_docs')).toBeInTheDocument();
  expect(screen.getByText('docs-server · read_page')).toBeInTheDocument();
  expect(screen.getByText('<0.1 ms')).toBeInTheDocument();
});

it('shows intercept-point state without fake controls and gates blacklist writes', async () => {
  await i18n.changeLanguage('zh-CN');
  access.canWrite = false;
  const view = render(<RuntimePage />);
  expect(screen.getByText('旁路')).toBeInTheDocument();
  expect(screen.getByText('已停用')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /添加规则/ })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: '删除' })).not.toBeInTheDocument();
  expect(screen.getByRole('switch')).toBeDisabled();
  access.canWrite = true;
  view.rerender(<RuntimePage />);
  expect(screen.getByRole('button', { name: /添加规则/ })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: '删除' })).toBeInTheDocument();
  expect(screen.getByRole('switch')).not.toBeDisabled();
});

it('sends the displayed version once and refreshes after a conflict without retrying', async () => {
  await i18n.changeLanguage('zh-CN');
  access.canWrite = true;
  let rejectWrite!: (error: Error) => void;
  writes.update.mockImplementationOnce(() => new Promise<undefined>((_, reject) => { rejectWrite = reject; }));
  render(<RuntimePage />);
  const toggle = screen.getByRole('switch');
  fireEvent.click(toggle);
  expect(writes.update).toHaveBeenCalledWith('rule-one', false, 7);
  expect(toggle).toBeDisabled();
  fireEvent.click(toggle);
  expect(writes.update).toHaveBeenCalledTimes(1);
  rejectWrite(Object.assign(new Error('黑名单已被其他人修改，请重新加载后确认'), { status: 409 }));
  await waitFor(() => expect(writes.refetch).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(toggle).not.toBeDisabled());
  expect(writes.update).toHaveBeenCalledTimes(1);
  expect(writes.remove).not.toHaveBeenCalled();
});

it('deletes using the displayed version and then reloads the authoritative list', async () => {
  await i18n.changeLanguage('zh-CN');
  access.canWrite = true;
  render(<RuntimePage />);
  fireEvent.click(screen.getByRole('button', { name: '删除' }));
  expect(writes.remove).toHaveBeenCalledWith('rule-one', 7);
  await waitFor(() => expect(writes.refetch).toHaveBeenCalledTimes(1));
  expect(writes.update).not.toHaveBeenCalled();
});
