import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ConfigProvider } from 'antd';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import AliCloudPage from './AliCloudPage';
vi.mock('@/api/client', () => ({ api: {}, useApiQuery: () => ({ data: { data: [] }, isLoading: false,
  error: null, refetch: async () => ({ data: { data: [] } }) }) }));
vi.mock('./alicloud/CloudConnections', () => ({ default: () => <div /> }));
vi.mock('./alicloud/AgentTeamsAuditPanel', () => ({ default: () => <div /> }));
vi.mock('./alicloud/WorkerQuotasPanel', () => ({ default: () => <div /> }));
vi.mock('./alicloud/TeamManagementPanel', () => ({ default: () => <div /> }));
vi.mock('./alicloud/mse/MseInventoryPanel', () => ({ default: () => <div /> }));
vi.mock('./alicloud/mse-config-publication/MseConfigPublicationPanel', () => ({ default: () => <div /> }));
vi.mock('./alicloud/privatelink/PrivateLinkInventoryPanel', () => ({ default: () => <div /> }));
vi.mock('./alicloud/apig-policy-publication/ApigPolicyPublicationPanel', () => ({ default: () => <div /> }));
vi.mock('./alicloud/scheduler-native/SchedulerNativePanel', () => ({ default: () => <div /> }));
vi.mock('./alicloud/task-handling/TaskHandlingPanel', () => ({ default: () => <div /> }));
vi.mock('./alicloud/agentteams-role-mapping/RoleMappingPanel', () => ({ default: () => <div /> }));
vi.mock('./alicloud/agentteams-orchestration/OrchestrationPanel', () => ({ default: () => <div /> }));
vi.mock('./alicloud/scheduler-managed/SchedulerManagedJobsPanel', () => ({ default: () => <div data-testid="scheduler-managed">scheduler-managed</div> }));
vi.mock('./alicloud/cms-queue/CmsQueuePanel', () => ({ default: () => <div data-testid="cms-queue">cms-queue</div> }));
vi.mock('./alicloud/apig-configuration-publication/ApigConfigurationPublicationPanel', () => ({ default: () => <div data-testid="apig-config">apig-config</div> }));
vi.mock('./alicloud/privatelink-provisioning/PrivateLinkProvisioningPanel', () => ({ default: () => <div data-testid="privatelink-provisioning">privatelink-provisioning</div> }));
vi.mock('./alicloud/BindingsPanel', () => ({ BindingsPanel: () => <div /> }));
vi.mock('./alicloud/CrossCallsPanel', () => ({ CrossCallsPanel: () => <div /> }));
vi.mock('./alicloud/SelfCheckPanel', () => ({ SelfCheckPanel: () => <div /> }));
vi.mock('./alicloud/TeamMembersPanel', () => ({ TeamMembersPanel: () => <div /> }));
vi.mock('./alicloud/TeamTable', () => ({ TeamTable: () => <div data-testid="inventory-panel">inventory</div> }));
afterEach(async () => { cleanup(); await i18n.changeLanguage('zh-CN'); });
function Location() { const location = useLocation(); return <output data-testid="query">{location.search}</output>; }
function mount(tab: string) {
  return render(<ConfigProvider theme={{ token: { motion: false } }}>
    <MemoryRouter initialEntries={[`/alicloud?tab=${tab}&source=existing-source&request_id=original-id`]}>
      <AliCloudPage /><Location />
    </MemoryRouter></ConfigProvider>);
}
const cases = [
  ['en-US', 'scheduler-managed', 'Scheduler managed jobs'],
  ['en-US', 'cms-queue', 'CMS durable delivery queue'],
  ['en-US', 'apig-config', 'APIG configuration and publication'],
  ['en-US', 'privatelink-provisioning', 'PrivateLink creation and acceptance'],
  ['zh-CN', 'scheduler-managed', 'Scheduler 受管任务'],
  ['zh-CN', 'cms-queue', 'CMS 持久补传队列'],
  ['zh-CN', 'apig-config', 'APIG 配置与发布'],
  ['zh-CN', 'privatelink-provisioning', 'PrivateLink 创建与接纳'],
] as const;
it.each(cases)('opens the actual managed page from a deep link in %s: %s', async (language, tab, label) => {
  await i18n.changeLanguage(language); mount(tab);
  expect(screen.getByTestId(tab)).toBeVisible();
  expect(screen.getByRole('tab', { name: label })).toHaveAttribute('aria-selected', 'true');
  fireEvent.click(screen.getByRole('tab', { name: language === 'zh-CN' ? '团队盘点与指标' : 'Team inventory and metrics' }));
  expect(screen.getByTestId('inventory-panel')).toBeVisible();
  const query = new URLSearchParams(screen.getByTestId('query').textContent!);
  expect(query.get('tab')).toBe('inventory');
  expect(query.get('source')).toBe('existing-source'); expect(query.get('request_id')).toBe('original-id');
});
it('uses the inventory page for an unknown deep link', async () => {
  await i18n.changeLanguage('en-US'); mount('unknown-managed-route');
  expect(screen.getByTestId('inventory-panel')).toBeVisible();
  expect(screen.getByRole('tab', { name: 'Team inventory and metrics' })).toHaveAttribute('aria-selected', 'true');
});
