import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { integrationsApi, type IntegrationConfig } from '@/api/integrations';
import IntegrationOperations from './IntegrationOperations';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: () => ({ has: () => true }) }));

const meta = { source: 'live' as const, elapsedMs: 1, at: Date.now() };
const config: IntegrationConfig = { name: 'webhook', version: 7, enabled: true, mock: false,
  environmentMock: false, settingsJson: '{}', secretKeys: [], probe: null,
  metadata: { requiredSecrets: ['webhook_url'], optionalSecrets: [], endpointKey: null, degradation: '', semantics: {} } };

describe('integration operation workflow', () => {
  it('requires explicit live intent and retains exactly the same request after a network error', async () => {
    const history = vi.spyOn(integrationsApi, 'history').mockResolvedValue({ data: { items: [] }, meta });
    const execute = vi.spyOn(integrationsApi, 'execute').mockRejectedValueOnce(new Error('connection interrupted'))
      .mockResolvedValueOnce({ data: { id: 'run-1', requestId: 'request-1', operation: 'send', configurationVersion: 7,
        actor: 'admin', startedAt: '2026-09-20T10:00:00Z', status: 'succeeded', mocked: false, receipt: { accepted: true } }, meta });
    const view = render(<IntegrationOperations snapshot={config} />);
    await waitFor(() => expect(history).toHaveBeenCalledOnce());
    fireEvent.change(screen.getByLabelText('标题'), { target: { value: 'Local validation' } });
    const button = screen.getByRole('button', { name: '执行业务调用' });
    expect(button).toBeDisabled();
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(button);
    await screen.findByText('connection interrupted');
    fireEvent.click(button);
    await screen.findByText('真实 · succeeded');
    expect(execute).toHaveBeenCalledTimes(2);
    expect(execute.mock.calls[0][1]).toEqual(execute.mock.calls[1][1]);
    expect(execute.mock.calls[0][1]).toMatchObject({ configuration_version: 7, confirm_live: true, operation: 'send' });
    expect(button).toBeDisabled();
    view.unmount(); history.mockRestore(); execute.mockRestore();
  });
  it('shows mock failures as failures and only offers supported operations', async () => {
    const history = vi.spyOn(integrationsApi, 'history').mockResolvedValue({ data: { items: [] }, meta });
    const execute = vi.spyOn(integrationsApi, 'execute').mockResolvedValue({ data: { id: 'run-2', requestId: 'request-2',
      operation: 'send', configurationVersion: 7, actor: 'admin', startedAt: '2026-09-20T10:00:00Z', status: 'failed',
      mocked: true, receipt: { error: 'Invalid local sample' } }, meta });
    const view = render(<IntegrationOperations snapshot={{ ...config, mock: true }} />);
    fireEvent.change(screen.getByLabelText('标题'), { target: { value: 'Mock validation' } });
    expect(screen.queryByRole('checkbox')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: '执行模拟调用' }));
    await screen.findByText('模拟 · failed');
    expect(screen.queryByText('真实 · succeeded')).toBeNull();
    expect(screen.queryByText('增量读取')).toBeNull();
    view.unmount(); history.mockRestore(); execute.mockRestore();
  });
  it('offers only read operations for a live EDR integration', async () => {
    const history = vi.spyOn(integrationsApi, 'history').mockResolvedValue({ data: { items: [] }, meta });
    const view = render(<IntegrationOperations snapshot={{ ...config, name: 'edr-isolation',
      metadata: { ...config.metadata, semantics: { pull: 'implemented' } } }} />);
    await screen.findByText(/EDR 真实隔离只能通过案件审批|Live EDR isolation requires case approval/);
    await waitFor(() => expect((screen.getByLabelText(/请求内容 JSON|Request JSON/) as HTMLTextAreaElement).value).toContain('"hosts"'));
    expect(screen.queryByLabelText(/标题|Title/)).toBeNull();
    view.unmount(); history.mockRestore();
  });
  it('keeps live SCIM deactivation in approved cases and sends only mock samples here', async () => {
    const history = vi.spyOn(integrationsApi, 'history').mockResolvedValue({ data: { items: [] }, meta });
    const live = render(<IntegrationOperations snapshot={{ ...config, name: 'iam-scim' }} />);
    await screen.findByText(/SCIM 真实身份停用只能通过案件审批|Live SCIM identity deactivation requires case approval/);
    expect(screen.queryByRole('button', { name: '执行业务调用' })).toBeNull();
    expect(screen.queryByLabelText(/目标 SCIM 用户编号|Target SCIM user ID/)).toBeNull();
    live.unmount();
    const execute = vi.spyOn(integrationsApi, 'execute').mockResolvedValue({ data: {
      id: 'mock-scim', requestId: 'request-scim', operation: 'send', configurationVersion: 7,
      actor: 'admin', startedAt: '2026-09-20T10:00:00Z', status: 'succeeded', mocked: true,
      receipt: { accepted: true },
    }, meta });
    const mock = render(<IntegrationOperations snapshot={{ ...config, name: 'iam-scim', mock: true }} />);
    fireEvent.change(screen.getByLabelText('标题'), { target: { value: 'Test user deactivation' } });
    fireEvent.change(screen.getByLabelText(/目标 SCIM 用户编号|Target SCIM user ID/), { target: { value: 'user-42' } });
    fireEvent.click(screen.getByRole('button', { name: '执行模拟调用' }));
    await screen.findByText('模拟 · succeeded');
    expect(execute.mock.calls[0][1]).toMatchObject({ operation: 'send', payload: {
      event_type: 'enforce.deactivate-user', labels: { user_id: 'user-42', action: 'deactivate' },
    } });
    mock.unmount(); history.mockRestore(); execute.mockRestore();
  });
});
