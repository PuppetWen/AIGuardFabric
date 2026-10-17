import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiRequestError } from '@/api/client';
import { automationsApi, type Automation } from '@/api/soarAutomations';
import i18n from '@/locales/i18n';
import AutomationEditor from './AutomationEditor';

const caches: QueryClient[] = [];
const meta = { source: 'live' as const, elapsedMs: 1, at: Date.now() };
const definition = { key: 'existing-case-review', name: 'Reviewed existing configuration',
  trigger: { min_severity: 'high' }, require_approval: true,
  steps: [{ name: 'Analyst review', params: { condition: 'true' } }] };
afterEach(async () => {
  cleanup(); caches.forEach(cache => cache.clear()); caches.length = 0; vi.restoreAllMocks();
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});
function mount(item?: Automation) {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } }); caches.push(cache);
  vi.spyOn(automationsApi, 'templates').mockResolvedValue({ data: { items: [] }, meta });
  const onSaved = vi.fn();
  render(<QueryClientProvider client={cache}><AutomationEditor item={item} onSaved={onSaved} onClose={vi.fn()} /></QueryClientProvider>);
  return onSaved;
}

describe('automatic response configuration capacity', () => {
  it.each(['en-US', 'zh-CN'])('explains the 50-slot limit in %s and retains the complete unsaved configuration after rejection', async language => {
    await i18n.changeLanguage(language);
    const zh = language === 'zh-CN';
    const advanced = zh ? '高级 YAML / JSON 编辑' : 'Advanced YAML / JSON editor';
    const reason = zh ? '变更说明' : 'Change reason';
    const review = zh ? '企业双人复核：由发布者以外的管理员批准' : 'Two-person review: require a different administrator';
    const save = vi.spyOn(automationsApi, 'save').mockRejectedValue(new ApiRequestError('soar-automation: 每租户最多 50 个配置', 400, 'validation', false));
    const onSaved = mount();
    expect(screen.getByText(zh ? '每租户最多 50 个自动响应配置，已停用的配置也占名额。' : 'Each tenant supports at most 50 automation configurations. Disabled configurations still occupy a slot.')).toBeInTheDocument();
    expect(screen.getByText(zh ? /达到上限时，保存会失败并保留草稿/ : /At capacity, saving fails and keeps your draft/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('checkbox', { name: advanced }));
    const yaml = JSON.stringify(definition, null, 2);
    fireEvent.change(screen.getByLabelText('Playbook YAML'), { target: { value: yaml } });
    fireEvent.change(screen.getByRole('textbox', { name: reason }), { target: { value: 'Keep reviewed draft after capacity failure' } });
    fireEvent.click(screen.getByRole('checkbox', { name: review }));
    fireEvent.click(screen.getByRole('switch'));
    fireEvent.click(screen.getByRole('button', { name: zh ? '保存配置' : 'Save configuration' }));
    await screen.findByText('soar-automation: 每租户最多 50 个配置');
    expect(screen.getByLabelText('Playbook YAML')).toHaveValue(yaml);
    expect(screen.getByRole('textbox', { name: reason })).toHaveValue('Keep reviewed draft after capacity failure');
    expect(screen.getByRole('checkbox', { name: review })).toBeChecked();
    expect(screen.getByRole('switch')).toBeChecked(); expect(onSaved).not.toHaveBeenCalled();
    expect(save).toHaveBeenCalledOnce(); expect(save).toHaveBeenCalledWith(undefined, {
      yaml, expected_version: 0, enabled: true, separate_approver: true, reason: 'Keep reviewed draft after capacity failure' });
  });

  it('allows editing an existing configuration without requiring a new slot', async () => {
    await i18n.changeLanguage('zh-CN');
    const item: Automation = { id: 'existing-auto', version: 7, enabled: false, separateApprover: false,
      since: '2026-09-30T00:00:00Z', history: [], playbook: definition };
    const save = vi.spyOn(automationsApi, 'save').mockResolvedValue({ data: { automation: { ...item, version: 8 } }, meta });
    const onSaved = mount(item);
    expect(screen.queryByText('每租户最多 50 个自动响应配置，已停用的配置也占名额。')).not.toBeInTheDocument();
    fireEvent.change(screen.getByRole('textbox', { name: '自动响应名称' }), { target: { value: '复用已有配置' } });
    fireEvent.change(screen.getByRole('textbox', { name: '变更说明' }), { target: { value: '复用名额，保留人工审批' } });
    fireEvent.click(screen.getByRole('button', { name: '保存配置' }));
    await waitFor(() => expect(onSaved).toHaveBeenCalledOnce());
    expect(save).toHaveBeenCalledWith('existing-auto', expect.objectContaining({ expected_version: 7, enabled: false,
      reason: '复用名额，保留人工审批', playbook: expect.objectContaining({ name: '复用已有配置', require_approval: true }) }));
  });
});
