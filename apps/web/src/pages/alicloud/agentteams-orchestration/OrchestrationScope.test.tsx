import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import type { ApiResult } from '@/api/dataSource';
import { agentteamsOrchestrationApi as api } from '@/api/agentteamsOrchestration';
import i18n from '@/locales/i18n';
import OrchestrationPanel from './OrchestrationPanel';
import type { Receipt, State } from './types';
import { deferred, receipt, requestId, result, state, tenantId } from './testFixtures';
import { installHarness, mount } from './testHarness';
import { apply, prepare, selectTeam } from './testInteractions';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('retains early recovery input identity and focus when the initial GET inserts current state, without an automatic receipt GET', async () => {
  const pending = deferred<ApiResult<State>>(); vi.mocked(api.state).mockReturnValueOnce(pending.promise);
  mount(<OrchestrationPanel />); const input = screen.getByRole('textbox', { name: 'Original orchestration request UUID' });
  input.focus(); fireEvent.change(input, { target: { value: requestId } });
  await act(async () => pending.resolve(result(state()))); await screen.findByRole('combobox', { name: 'Observed Team' });
  expect(screen.getByRole('textbox', { name: 'Original orchestration request UUID' })).toBe(input); expect(input.isConnected).toBe(true);
  expect(input).toHaveValue(requestId); expect(input).toHaveFocus(); expect(api.receipt).not.toHaveBeenCalled(); expect(api.apply).not.toHaveBeenCalled();
});

it.each(['tenant', 'session', 'A-B-A'] as const)('discards a late state after %s changes and does not restore old inventory or drafts', async change => {
  const pending = deferred<ApiResult<State>>(); vi.mocked(api.state).mockReturnValueOnce(pending.promise).mockResolvedValue(result(state({ teams: [], records: [] })));
  mount(<OrchestrationPanel />); const oldSignal = vi.mocked(api.state).mock.calls[0][0];
  await act(async () => {
    if (change === 'session') useAuthStore.setState({ sessionGeneration: 2 });
    else useAuthStore.setState({ tenant: { id: '20000000-0000-5000-8000-000000000001', slug: 'second' } as Tenant, sessionGeneration: 2 });
  });
  if (change === 'A-B-A') await act(async () => useAuthStore.setState({ tenant: { id: tenantId, slug: 'owned' } as Tenant, sessionGeneration: 3 }));
  await act(async () => pending.resolve(result(state()))); await waitFor(() => expect(api.state).toHaveBeenCalledTimes(change === 'A-B-A' ? 3 : 2));
  expect(oldSignal?.aborted).toBe(true); expect(screen.queryByText('Owned Team')).not.toBeInTheDocument();
  expect(screen.queryByRole('textbox', { name: 'DAG declaration JSON' })).not.toBeInTheDocument(); expect(api.apply).not.toHaveBeenCalled();
});

it('tenant/session change discards a late successful PUT, clears the prior request UUID and does not replay it', async () => {
  const pending = deferred<ApiResult<Receipt>>(); vi.mocked(api.apply).mockReturnValue(pending.promise);
  mount(<OrchestrationPanel />); await selectTeam(); await prepare(); await apply(false); await waitFor(() => expect(api.apply).toHaveBeenCalledTimes(1));
  const body = vi.mocked(api.apply).mock.calls[0][1], signal = vi.mocked(api.apply).mock.calls[0][2];
  vi.mocked(api.state).mockResolvedValue(result(state({ teams: [], records: [] })));
  await act(async () => useAuthStore.setState({ tenant: { id: '20000000-0000-5000-8000-000000000001', slug: 'second' } as Tenant, sessionGeneration: 2 }));
  await act(async () => pending.resolve(result(receipt(body))));
  expect(signal?.aborted).toBe(true); expect(screen.getByRole('textbox', { name: 'Original orchestration request UUID' })).toHaveValue('');
  expect(screen.queryByText('Immutable original receipt')).not.toBeInTheDocument(); expect(api.apply).toHaveBeenCalledTimes(1); expect(api.receipt).not.toHaveBeenCalled();
});

it.each([
  ['en-US', 'Orchestration and three onboarding modes guide', /feature does not support Live/, /SDK mode explicitly installs\/wraps calls/],
  ['zh-CN', '编排定义与三种接入模式指南', /Live 不支持此功能/, /SDK 模式显式安装并包裹调用/],
] as const)('shows the %s operating boundaries and actual onboarding links without writes', async (language, title, live, sdk) => {
  await i18n.changeLanguage(language); mount(<OrchestrationPanel />); fireEvent.click(screen.getByText(title));
  await screen.findByText(live); expect(screen.getByText(sdk)).toBeInTheDocument();
  const agentLabel = language === 'zh-CN' ? 'Agent 管理' : 'Agent management';
  expect(screen.getByRole('link', { name: agentLabel })).toHaveAttribute('href', '/agents');
  expect(api.preview).not.toHaveBeenCalled(); expect(api.apply).not.toHaveBeenCalled();
});
