import { ConfigProvider } from 'antd';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import { SchedulerGuide } from '../SchedulerGuide';
import { SchedulerCallbackPreparation } from './SchedulerCallbackPreparation';

const tenantId = 'a12bc345-6789-4abc-8def-0123456789ab';
const otherTenant = 'b23cd456-7890-4bcd-9efa-1234567890bc';
const originalAuth = useAuthStore.getState();
const originalClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
let writes: ReturnType<typeof vi.fn>;
let fetchSpy: ReturnType<typeof vi.fn>;
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  useAuthStore.setState({ tenant: { id: tenantId, slug: 'one' } as Tenant, sessionGeneration: 1 });
  writes = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', { value: { writeText: writes }, configurable: true });
  fetchSpy = vi.fn().mockRejectedValue(new Error('Unexpected network request'));
  vi.stubGlobal('fetch', fetchSpy);
});
afterEach(async () => {
  cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); useAuthStore.setState(originalAuth);
  if (originalClipboard) Object.defineProperty(navigator, 'clipboard', originalClipboard);
  else Reflect.deleteProperty(navigator, 'clipboard');
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});
function mount(guide = false) {
  return render(<ConfigProvider theme={{ token: { motion: false } }}>
    {guide ? <SchedulerGuide /> : <SchedulerCallbackPreparation />}
  </ConfigProvider>);
}
function fill(origin = 'https://scheduler.example.com:9443') {
  fireEvent.change(screen.getByRole('textbox', { name: 'Scheduler callback HTTPS origin' }), { target: { value: origin } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Actual cloud HTTP application AppId' }), { target: { value: '123' } });
}
function select(kind: string) { fireEvent.click(screen.getByRole('checkbox', { name: new RegExp(`^${kind} —`) })); }
function generate() { fireEvent.click(screen.getByRole('button', { name: 'Generate callback preparation' })); }
function output() { return screen.getByRole('textbox', { name: 'Non-secret callback preparation' }); }
function outputText() { return (output() as HTMLTextAreaElement).value; }

it('prepares selected callbacks without network calls or real secrets and copies only after an explicit click', async () => {
  mount(); fill(); select('log-pull'); select('archive'); generate();
  const material = JSON.parse(outputText());
  expect(material.tasks.map((task: { kind: string }) => task.kind)).toEqual(['log-pull', 'archive']);
  expect(material.deployment.AGF_SCHEDULER_TENANT_ID).toBe(tenantId);
  expect(material.requiredSecretReferences.AGF_SCHEDULER_CALLBACK_TOKEN.supplyFromDeploymentSecret).toBe(true);
  expect(screen.getByText('2 tasks prepared; registration and deployment remain unverified')).toBeInTheDocument();
  expect(screen.queryByLabelText(/token/i)).not.toBeInTheDocument();
  expect(writes).not.toHaveBeenCalled(); expect(fetchSpy).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Copy non-secret preparation' }));
  await screen.findByText('Preparation copied; no tasks were registered or executed.');
  expect(writes).toHaveBeenCalledTimes(1); expect(writes).toHaveBeenCalledWith(outputText());
  expect(fetchSpy).not.toHaveBeenCalled();
});

it('requires explicit task selection and rejects unsafe input without preserving previously generated material', () => {
  mount(); fill(); generate();
  expect(screen.getByText('Explicitly select at least one task.')).toBeInTheDocument();
  expect(screen.queryByRole('textbox', { name: 'Non-secret callback preparation' })).not.toBeInTheDocument();
  select('report'); generate(); expect(outputText()).toContain('/api/v1/internal/jobs/report');
  fireEvent.change(screen.getByRole('textbox', { name: 'Scheduler callback HTTPS origin' }), {
    target: { value: 'https://user:password@scheduler.example.com/a/..' },
  });
  generate(); expect(screen.getByText(/Enter an HTTPS origin/)).toBeInTheDocument();
  expect(screen.queryByRole('textbox', { name: 'Non-secret callback preparation' })).not.toBeInTheDocument();
  expect(fetchSpy).not.toHaveBeenCalled(); expect(writes).not.toHaveBeenCalled();
});

it('retains manually copyable material when actual clipboard write fails', async () => {
  writes.mockRejectedValue(new Error('Permission denied'));
  mount(); fill(); select('report'); generate(); const before = outputText();
  fireEvent.click(screen.getByRole('button', { name: 'Copy non-secret preparation' }));
  await screen.findByText(/Clipboard access is unavailable or failed/);
  expect(outputText()).toBe(before);
  expect(screen.queryByText('Preparation copied; no tasks were registered or executed.')).not.toBeInTheDocument();
  expect(fetchSpy).not.toHaveBeenCalled();
});

it('provides manual copying when the browser has no clipboard API', async () => {
  Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
  mount(); fill(); select('report'); generate();
  fireEvent.click(screen.getByRole('button', { name: 'Copy non-secret preparation' }));
  await screen.findByText(/Clipboard access is unavailable or failed/);
  expect(outputText()).toContain('preparation_only'); expect(writes).not.toHaveBeenCalled();
});

it.each(['tenant', 'session', 'tenant round-trip'])('clears drafts and ignores a late clipboard result after %s changes', async change => {
  let complete!: () => void;
  writes.mockImplementation(() => new Promise<void>(resolve => { complete = resolve; }));
  mount(); fill(); select('asset-inventory'); generate();
  fireEvent.click(screen.getByRole('button', { name: 'Copy non-secret preparation' }));
  await waitFor(() => expect(writes).toHaveBeenCalledTimes(1));
  act(() => {
    if (change !== 'session') useAuthStore.setState({ tenant: { id: otherTenant, slug: 'two' } as Tenant, sessionGeneration: 2 });
    if (change === 'tenant round-trip') useAuthStore.setState({ tenant: { id: tenantId, slug: 'one' } as Tenant, sessionGeneration: 3 });
    if (change === 'session') useAuthStore.setState({ sessionGeneration: 2 });
  });
  expect(screen.getByRole('textbox', { name: 'Scheduler callback HTTPS origin' })).toHaveValue('');
  expect(screen.getByRole('textbox', { name: 'Actual cloud HTTP application AppId' })).toHaveValue('');
  expect(screen.getByRole('checkbox', { name: /^asset-inventory —/ })).not.toBeChecked();
  expect(screen.getByRole('textbox', { name: 'Current deployment tenant UUID' })).toHaveValue(change === 'tenant' ? otherTenant : tenantId);
  await act(async () => { complete(); });
  expect(screen.queryByRole('textbox', { name: 'Non-secret callback preparation' })).not.toBeInTheDocument();
  expect(screen.queryByText('Preparation copied; no tasks were registered or executed.')).not.toBeInTheDocument();
  expect(fetchSpy).not.toHaveBeenCalled();
});

it('keeps current material through a token refresh in the same tenant and session', () => {
  mount(); fill(); select('report'); generate(); const before = outputText();
  act(() => useAuthStore.setState({ token: 'new-test-token' }));
  expect(outputText()).toBe(before); expect(fetchSpy).not.toHaveBeenCalled();
});

it.each(['en-US', 'zh-CN'])('shows all six real targets and independent timers in %s without automatic requests', async language => {
  await i18n.changeLanguage(language); mount(true);
  const zh = language === 'zh-CN';
  expect(screen.getByText(zh ? '受管任务与实际部署分别核验' : 'Verify managed jobs and actual deployment separately')).toBeInTheDocument();
  expect(screen.getByText(zh
    ? /受管页支持六类停用 Mock 声明，以及已有 HTTP Job 的日历\/重试修改和独立启停/
    : /Managed jobs support six disabled Mock declarations and calendar\/retry changes plus separate enable\/disable/)).toBeInTheDocument();
  expect(screen.getByText(zh
    ? /Live 新建所需 HTTP 执行器载荷合同尚未验证，当前会拒绝创建/
    : /The Live HTTP creation payload contract remains unverified and creation is rejected/)).toBeInTheDocument();
  expect(screen.getByRole('link', { name: zh
    ? '打开受管任务：预览修改、启停、原编号恢复与历史归档'
    : 'Open managed jobs: preview changes, enable/disable, original-ID recovery and history archive' }))
    .toHaveAttribute('href', '/alicloud?tab=scheduler-managed');
  expect(screen.getByText(zh ? '六类任务：真实目标与验收' : 'Six tasks: actual targets and verification')).toBeInTheDocument();
  expect(screen.getAllByRole('checkbox')).toHaveLength(6);
  expect(screen.getByText('AGF_SCHEDULER_REPORT_GENERATE_ENABLED')).toBeInTheDocument();
  expect(screen.getByText('AGF_SCHEDULER_COLD_ARCHIVE_ENABLED')).toBeInTheDocument();
  expect(screen.getByText(zh ? /主服务 HTTP Pull 到期扫描、业务报表计划和每日资产快照仍独立运行/ : /Main-service HTTP Pull scanning, business report plans and daily asset snapshots remain independent/)).toBeInTheDocument();
  expect(screen.getByText(zh ? /当前不执行真实目标攻击或 CI gate/ : /it does not run live attacks or a CI gate/)).toBeInTheDocument();
  expect(screen.getByText(zh ? /不是事件库 Parquet 或云日志清理/ : /not event Parquet or cloud-log deletion/)).toBeInTheDocument();
  expect(fetchSpy).not.toHaveBeenCalled(); expect(writes).not.toHaveBeenCalled();
});
