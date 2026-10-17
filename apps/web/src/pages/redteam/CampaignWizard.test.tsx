import { message } from 'antd';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import * as transport from '@/api/transport';
import i18n from '@/locales/i18n';
import { CampaignWizard } from './CampaignWizard';

vi.mock('@/api/client', () => ({
  useApiQuery: (key: string, _query: unknown, options?: { key?: string[] }) => ({
    data: { data: { items: key === 'wizard-agent-targets'
      ? [{ id: 'target-1', name: 'Fixture Agent', model: 'fixture-model', enabled: true, version: 3 }]
      : key === 'wizard-mcp-targets'
        ? [{ id: 'mcp-1', name: 'Fixture MCP', toolName: 'safe_query', enabled: true, version: 2 }]
        : options?.key?.[0] === 'mcp-http'
          ? [{ key: 'RT-MCP-001', title: 'MCP canary' }, { key: 'RT-MCP-003', title: 'Cross-tool canary' }]
          : [{ key: 'RT-DI-031', title: 'Canary leak' }] } }, isLoading: false, error: null,
  }),
}));

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it('submits a version-pinned real Agent campaign without simulator settings', async () => {
  await i18n.changeLanguage('en-US');
  const send = vi.spyOn(transport, 'callApi').mockResolvedValue({ data: { taskId: 'campaign-1' },
    meta: { source: 'live', elapsedMs: 1, at: Date.now() } });
  const submitted = vi.fn();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><CampaignWizard open canUseAgentTarget onClose={vi.fn()} onSubmitted={submitted} />
    </QueryClientProvider>);
  fireEvent.change(screen.getByLabelText('Campaign name'), { target: { value: 'Real target test' } });
  fireEvent.mouseDown(screen.getByLabelText('Execution mode'));
  fireEvent.click((await screen.findAllByText('Real Agent HTTP')).at(-1)!);
  fireEvent.mouseDown(screen.getByLabelText('Connected Agent target'));
  fireEvent.click((await screen.findAllByText(/Fixture Agent/)).at(-1)!);
  fireEvent.mouseDown(screen.getByLabelText('Cases with a supported oracle (up to 20)'));
  fireEvent.click((await screen.findAllByText(/RT-DI-031/)).at(-1)!);
  fireEvent.click(screen.getByRole('button', { name: 'Submit campaign' }));
  await waitFor(() => expect(submitted).toHaveBeenCalledWith('campaign-1'));
  expect(send).toHaveBeenCalledWith('/api/v1/redteam/campaigns', expect.any(Function),
    expect.objectContaining({ noFallback: true, body: expect.objectContaining({
      execution_mode: 'agent-http', target_profile_id: 'target-1', target_profile_version: 3,
      case_keys: ['RT-DI-031'], max_cases: 1,
    }) }));
  const options = send.mock.calls[0]?.[2] as { body: Record<string, unknown> };
  expect(options.body).not.toHaveProperty('guard_strength');
  expect(options.body).not.toHaveProperty('target_name');
});

it('submits only the fixed MCP canary case with a pinned target version', async () => {
  await i18n.changeLanguage('en-US');
  const send = vi.spyOn(transport, 'callApi').mockResolvedValue({ data: { taskId: 'mcp-campaign' },
    meta: { source: 'live', elapsedMs: 1, at: Date.now() } });
  const submitted = vi.fn();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><CampaignWizard open canUseAgentTarget canUseMcpTarget
    onClose={vi.fn()} onSubmitted={submitted} /></QueryClientProvider>);
  fireEvent.change(screen.getByLabelText('Campaign name'), { target: { value: 'MCP probe' } });
  fireEvent.mouseDown(screen.getByLabelText('Execution mode'));
  fireEvent.click((await screen.findAllByText('Real MCP HTTP')).at(-1)!);
  fireEvent.mouseDown(screen.getByLabelText('Connected MCP target'));
  fireEvent.click((await screen.findAllByText(/Fixture MCP/)).at(-1)!);
  fireEvent.mouseDown(screen.getByLabelText('Cases with a supported oracle (up to 20)'));
  fireEvent.click((await screen.findAllByText(/RT-MCP-001/)).at(-1)!);
  fireEvent.click(screen.getByRole('button', { name: 'Submit campaign' }));
  await waitFor(() => expect(submitted).toHaveBeenCalledWith('mcp-campaign'));
  expect(send).toHaveBeenCalledWith('/api/v1/redteam/campaigns', expect.any(Function),
    expect.objectContaining({ body: expect.objectContaining({
      execution_mode: 'mcp-http', target_profile_id: 'mcp-1', target_profile_version: 2,
      case_keys: ['RT-MCP-001'], max_cases: 1,
    }) }));
});

it('keeps a cross-tool campaign local when the target has no detail tool', async () => {
  await i18n.changeLanguage('en-US');
  const errorMessage = vi.spyOn(message, 'error');
  const send = vi.spyOn(transport, 'callApi').mockResolvedValue({ data: { taskId: 'unexpected' },
    meta: { source: 'live', elapsedMs: 1, at: Date.now() } });
  const submitted = vi.fn();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><CampaignWizard open canUseAgentTarget canUseMcpTarget
    onClose={vi.fn()} onSubmitted={submitted} /></QueryClientProvider>);
  fireEvent.change(screen.getByLabelText('Campaign name'), { target: { value: 'Cross-tool probe' } });
  fireEvent.mouseDown(screen.getByLabelText('Execution mode'));
  fireEvent.click((await screen.findAllByText('Real MCP HTTP')).at(-1)!);
  fireEvent.mouseDown(screen.getByLabelText('Connected MCP target'));
  fireEvent.click((await screen.findAllByText(/Fixture MCP/)).at(-1)!);
  fireEvent.mouseDown(screen.getByLabelText('Cases with a supported oracle (up to 20)'));
  fireEvent.click((await screen.findAllByText(/RT-MCP-003/)).at(-1)!);
  fireEvent.click(screen.getByRole('button', { name: 'Submit campaign' }));
  await waitFor(() => expect(errorMessage).toHaveBeenCalledWith(
    expect.stringContaining('Configure a read-only detail tool')));
  expect(send).not.toHaveBeenCalled();
  expect(submitted).not.toHaveBeenCalled();
});
