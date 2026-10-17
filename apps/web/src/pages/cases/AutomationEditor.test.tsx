import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { automationsApi, type Automation } from '@/api/soarAutomations';
import { integrationsApi } from '@/api/integrations';
import i18n from '@/locales/i18n';
import AutomationEditor from './AutomationEditor';

const caches: QueryClient[] = [];
afterEach(async () => {
  cleanup(); caches.forEach(cache => cache.clear()); caches.length = 0; vi.restoreAllMocks();
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});

describe('automatic response editing', () => {
  it('starts with a case-only template that has no response action', async () => {
    await i18n.changeLanguage('en-US');
    const meta = { source: 'live' as const, elapsedMs: 1, at: Date.now() };
    vi.spyOn(automationsApi, 'templates').mockResolvedValue({ data: { items: [] }, meta });
    const save = vi.spyOn(automationsApi, 'save').mockResolvedValue({ data: { automation: {} as Automation }, meta });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    caches.push(client);
    const rendered = render(<QueryClientProvider client={client}>
      <AutomationEditor onSaved={vi.fn()} onClose={vi.fn()} />
    </QueryClientProvider>);
    expect(screen.getByText('Creates a case linked to the alert, findings and assets, with no response action or external call.')).toBeInTheDocument();
    fireEvent.change(screen.getByRole('textbox', { name: 'Change reason' }), { target: { value: 'Triage only' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save configuration' }));
    await waitFor(() => expect(save).toHaveBeenCalledWith(undefined, expect.objectContaining({
      enabled: false,
      playbook: expect.objectContaining({ key: 'case-review-only', require_approval: false,
        steps: [{ name: 'Record case for analyst', params: { condition: 'true' } }] }),
    })));
    rendered.unmount(); client.clear(); vi.restoreAllMocks();
  });
  it('previews without saving and retains the reviewed revision and edits after a conflict', async () => {
    await i18n.changeLanguage('zh-CN');
    const meta = {source: 'live' as const, elapsedMs: 1, at: Date.now()};
    const item: Automation = { id: 'auto-one', version: 7, enabled: false, separateApprover: false, since: '2026-09-21T00:00:00Z', history: [],
      playbook: { key: 'block-reviewed', name: 'Reviewed block', trigger: { min_severity: 'high' }, require_approval: true,
        steps: [{name: 'Block reviewed domain', action: 'block-domain', params: {domain: 'reviewed.example'}}] } };
    vi.spyOn(automationsApi, 'templates').mockResolvedValue({data: {items: []}, meta});
    const preview = vi.spyOn(automationsApi, 'preview').mockResolvedValue({data: {matches: true, active: true, requiresApproval: true,
      context: { asset_ids: [], finding_ids: [], rule_keys: [], params: {} }, steps: ['Block reviewed domain']}, meta});
    const save = vi.spyOn(automationsApi, 'save').mockRejectedValue(new Error('配置版本冲突，请重新核对'));
    const onSaved = vi.fn();
    const client = new QueryClient({defaultOptions: {queries: {retry: false}}});
    caches.push(client);
    const rendered = render(<QueryClientProvider client={client}><AutomationEditor item={item} onSaved={onSaved} onClose={vi.fn()} /></QueryClientProvider>);
    fireEvent.change(screen.getByRole('textbox', {name: '封禁域名（不含协议、路径）'}), {target: {value: 'changed.example'}});
    fireEvent.click(screen.getByText('匹配预览（无副作用）'));
    fireEvent.change(screen.getByRole('textbox', {name: '预览告警 ID'}), {target: {value: 'alert-one'}});
    fireEvent.click(screen.getByRole('button', {name: '检查匹配与目标'}));
    await screen.findByText('匹配：请核对以下目标');
    expect(preview).toHaveBeenCalledWith(expect.objectContaining({alert_id: 'alert-one'}));
    expect(save).not.toHaveBeenCalled();
    fireEvent.change(screen.getByRole('textbox', {name: '变更说明'}), {target: {value: 'Reviewed only this domain'}});
    const saveButton = await screen.findByRole('button', {name: '保存配置'});
    await waitFor(() => expect(saveButton).toBeEnabled());
    fireEvent.click(saveButton);
    await screen.findByText('配置版本冲突，请重新核对');
    await waitFor(() => expect(save).toHaveBeenCalledWith('auto-one', expect.objectContaining({expected_version: 7,
      enabled: false, reason: 'Reviewed only this domain', playbook: expect.objectContaining({steps: [expect.objectContaining({params: {domain: 'changed.example'}})]})})));
    expect(screen.getByRole('textbox', {name: '变更说明'})).toHaveValue('Reviewed only this domain');
    expect(onSaved).not.toHaveBeenCalled();
    rendered.unmount(); client.clear(); vi.restoreAllMocks();
  });
  it('reads the SCIM binding and configuration instead of asking for remote IDs', async () => {
    await i18n.changeLanguage('zh-CN');
    const meta = {source: 'live' as const, elapsedMs: 1, at: Date.now()};
    const item: Automation = { id: 'auto-scim', version: 2, enabled: true, separateApprover: true,
      since: '2026-09-24T00:00:00Z', history: [], playbook: {
        key: 'review-scim-deactivation', name: 'Review SCIM user deactivation',
        trigger: { min_severity: 'high', asset_kinds: ['credential'] }, require_approval: true,
        steps: [{ name: 'Deactivate exact user', action: 'deactivate-external-user',
          params: { asset_id: '019f0000-0000-7000-8000-000000000001', user_id: '', configuration_version: 0, reason: '' } }],
      } };
    vi.spyOn(automationsApi, 'templates').mockResolvedValue({ data: { items: [] }, meta });
    vi.spyOn(integrationsApi, 'configuration').mockResolvedValue({ data: {
      name: 'iam-scim', enabled: true, mock: true, environmentMock: false, version: 3,
      settingsJson: '{}', secretKeys: [], probe: null, metadata: {
        requiredSecrets: [], optionalSecrets: [], endpointKey: 'endpoint', degradation: '', semantics: {},
      },
    }, meta });
    vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      const path = String(input);
      const asset = { id: '019f0000-0000-7000-8000-000000000001', name: 'Test identity',
        kind: 'credential', lifecycle: 'active', attributes: { scim_user_id: 'user-42' } };
      if (path.includes('/api/v1/assets/')) return Response.json({ asset });
      if (path.includes('/api/v1/assets')) return Response.json({ items: [asset] });
      throw new Error(`Unexpected request ${path}`);
    });
    const save = vi.spyOn(automationsApi, 'save').mockResolvedValue({ data: { automation: item }, meta });
    const client = new QueryClient({defaultOptions: {queries: {retry: false}}});
    caches.push(client);
    const rendered = render(<QueryClientProvider client={client}>
      <AutomationEditor item={item} onSaved={vi.fn()} onClose={vi.fn()} />
    </QueryClientProvider>);
    fireEvent.change(screen.getByRole('textbox', {name: '变更说明'}), {target: {value: 'Review exact external target'}});
    const button = screen.getByRole('button', {name: '保存配置'});
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByRole('textbox', {name: '停用原因'}), {target: {value: 'Confirmed compromise'}});
    await screen.findByText('已绑定远端编号 user-42 · iam-scim 配置版本 3 · Mock');
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    await waitFor(() => expect(save).toHaveBeenCalledWith('auto-scim', expect.objectContaining({
      enabled: true, playbook: expect.objectContaining({steps: [expect.objectContaining({
        params: expect.objectContaining({asset_id: '019f0000-0000-7000-8000-000000000001',
          user_id: 'user-42', configuration_version: 3}),
      })]}),
    })));
    rendered.unmount(); client.clear(); vi.restoreAllMocks();
  });
});
