import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import AliCloudPage from './AliCloudPage';

vi.mock('@/api/client', () => ({ api: {}, useApiQuery: () => ({ data: { data: [] },
  isLoading: false, error: null, refetch: vi.fn() }) }));
vi.mock('./alicloud/CloudConnections', () => ({ default: () => null }));
vi.mock('./alicloud/agentteams-orchestration/OrchestrationPanel', () => ({ default: () => <div data-testid="orchestration-panel">Orchestration definitions evidence</div> }));
vi.mock('./alicloud/AgentTeamsAuditPanel', () => ({ default: () => <div data-testid="audit-panel">Audit evidence</div> }));
vi.mock('./alicloud/task-handling/TaskHandlingPanel', () => ({ default: () => <div data-testid="task-handling-panel">Operator handling evidence</div> }));
vi.mock('./alicloud/agentteams-role-mapping/RoleMappingPanel', () => ({ default: () => <div data-testid="role-mapping-panel">Role permission mapping evidence</div> }));
vi.mock('./alicloud/WorkerQuotasPanel', () => ({ default: () => <div data-testid="quota-panel">Worker quota governance evidence</div> }));
vi.mock('./alicloud/mse-config-publication/MseConfigPublicationPanel', () => ({ default: () => <div data-testid="mse-publication-panel">MSE publication evidence</div> }));
vi.mock('./alicloud/TeamTable', () => ({ TeamTable: () => <div data-testid="inventory-panel">Inventory evidence</div> }));
vi.mock('./alicloud/CrossCallsPanel', () => ({ CrossCallsPanel: () => null }));
vi.mock('./alicloud/BindingsPanel', () => ({ BindingsPanel: () => null }));
vi.mock('./alicloud/SelfCheckPanel', () => ({ SelfCheckPanel: () => null }));

beforeEach(async () => { await i18n.changeLanguage('en-US'); });
afterEach(async () => { await i18n.changeLanguage('zh-CN'); });
function LocationProbe() { return <output data-testid="location-search">{useLocation().search}</output>; }
function mount(path: string) {
  return render(<MemoryRouter initialEntries={[path]}><AliCloudPage /><LocationProbe /></MemoryRouter>);
}

describe('Alibaba Cloud tab links', () => {
  it('opens orchestration directly and retains its original receipt and team when switching tabs', async () => {
    const view = mount('/alicloud?tab=agentteams-orchestration&orchestration_request_id=original-orchestration-receipt&team=worker-team&keep=operator-view');
    expect(await screen.findByRole('tab', { name: 'Orchestration definitions' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByTestId('orchestration-panel')).toBeInTheDocument();
    expect(screen.queryByTestId('inventory-panel')).not.toBeInTheDocument();
    expect(view.container.querySelector('.agf-page-header__actions')).toBeNull();
    fireEvent.click(screen.getByRole('tab', { name: 'Messages and call audit' }));
    const params = new URLSearchParams(screen.getByTestId('location-search').textContent ?? '');
    expect(params.get('orchestration_request_id')).toBe('original-orchestration-receipt');
    expect(params.get('team')).toBe('worker-team'); expect(params.get('keep')).toBe('operator-view');
    fireEvent.click(screen.getByRole('tab', { name: 'Orchestration definitions' }));
    expect(screen.getByRole('tab', { name: 'Orchestration definitions' })).toHaveAttribute('aria-selected', 'true');
  });
  it('selects the same orchestration deep link in the Chinese console', async () => {
    await i18n.changeLanguage('zh-CN'); mount('/alicloud?tab=agentteams-orchestration');
    expect(await screen.findByRole('tab', { name: '编排定义' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByTestId('orchestration-panel')).toBeInTheDocument();
  });
  it('opens Role mapping directly and preserves the original receipt across tab switches', async () => {
    const view = mount('/alicloud?tab=role-mapping&role_request_id=original-role-receipt&keep=worker-one');
    expect(await screen.findByRole('tab', { name: 'Role permission mapping' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByTestId('role-mapping-panel')).toBeInTheDocument();
    expect(screen.queryByTestId('inventory-panel')).not.toBeInTheDocument();
    expect(view.container.querySelector('.agf-page-header__actions')).toBeNull();
    fireEvent.click(screen.getByRole('tab', { name: 'Messages and call audit' }));
    const params = new URLSearchParams(screen.getByTestId('location-search').textContent ?? '');
    expect(params.get('role_request_id')).toBe('original-role-receipt'); expect(params.get('keep')).toBe('worker-one');
    fireEvent.click(screen.getByRole('tab', { name: 'Role permission mapping' }));
    expect(screen.getByRole('tab', { name: 'Role permission mapping' })).toHaveAttribute('aria-selected', 'true');
  });
  it('opens task handling directly and preserves the original request while switching tabs', async () => {
    mount('/alicloud?tab=task-handling&task_request_id=original-receipt&keep=worker-one');
    expect(await screen.findByRole('tab', { name: 'Errors and operator handling' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByTestId('task-handling-panel')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('tab', { name: 'Messages and call audit' }));
    const params = new URLSearchParams(screen.getByTestId('location-search').textContent ?? '');
    expect(params.get('task_request_id')).toBe('original-receipt'); expect(params.get('keep')).toBe('worker-one');
  });
  it('opens a MSE publication deep link and preserves its receipt when switching tabs', async () => {
    const view = mount('/alicloud?tab=mse-config&publication_request_id=receipt-one&keep=source-one');
    expect(await screen.findByRole('tab', { name: 'MSE configuration publication' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByTestId('mse-publication-panel')).toBeInTheDocument();
    expect(screen.queryByTestId('inventory-panel')).not.toBeInTheDocument();
    expect(view.container.querySelector('.agf-page-header__actions')).toBeNull();
    fireEvent.click(screen.getByRole('tab', { name: 'Messages and call audit' }));
    const params = new URLSearchParams(screen.getByTestId('location-search').textContent ?? '');
    expect(params.get('tab')).toBe('audit'); expect(params.get('keep')).toBe('source-one');
    expect(params.get('publication_request_id')).toBe('receipt-one');
    fireEvent.click(screen.getByRole('tab', { name: 'MSE configuration publication' }));
    expect(screen.getByRole('tab', { name: 'MSE configuration publication' })).toHaveAttribute('aria-selected', 'true');
  });

  it('opens an audit deep link directly', async () => {
    const view = mount('/alicloud?tab=audit&keep=source-one');
    expect(await screen.findByRole('tab', { name: 'Messages and call audit' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByTestId('audit-panel')).toBeInTheDocument();
    expect(screen.queryByTestId('inventory-panel')).not.toBeInTheDocument();
    expect(view.container.querySelector('.agf-page-header__actions')).toBeNull();
  });

  it('opens a Worker quotas deep link without the inventory refresh controls', async () => {
    const view = mount('/alicloud?tab=quotas&keep=worker-one');
    expect(await screen.findByRole('tab', { name: 'Worker quota governance' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByTestId('quota-panel')).toBeInTheDocument();
    expect(screen.queryByTestId('inventory-panel')).not.toBeInTheDocument();
    expect(screen.queryByTestId('audit-panel')).not.toBeInTheDocument();
    expect(view.container.querySelector('.agf-page-header__actions')).toBeNull();
  });

  it('preserves other query parameters across quota, audit and inventory tab switches', async () => {
    const view = mount('/alicloud?tab=inventory&keep=worker-one');
    for (const [key, label] of [['quotas', 'Worker quota governance'], ['audit', 'Messages and call audit'], ['inventory', 'Team inventory and metrics']]) {
      fireEvent.click(await screen.findByRole('tab', { name: label }));
      expect(screen.getByRole('tab', { name: label })).toHaveAttribute('aria-selected', 'true');
      const params = new URLSearchParams(screen.getByTestId('location-search').textContent ?? '');
      expect(params.get('tab')).toBe(key); expect(params.get('keep')).toBe('worker-one');
      if (key === 'inventory') expect(view.container.querySelector('.agf-page-header__actions')).not.toBeNull();
      else expect(view.container.querySelector('.agf-page-header__actions')).toBeNull();
    }
  });

  it('defaults an invalid tab to inventory and preserves other query parameters when switching', async () => {
    mount('/alicloud?tab=invalid&keep=source-one');
    expect(await screen.findByRole('tab', { name: 'Team inventory and metrics' })).toHaveAttribute('aria-selected', 'true');
    fireEvent.click(screen.getByRole('tab', { name: 'Messages and call audit' }));
    expect(await screen.findByRole('tab', { name: 'Messages and call audit' })).toHaveAttribute('aria-selected', 'true');
    let params = new URLSearchParams(screen.getByTestId('location-search').textContent ?? '');
    expect(params.get('tab')).toBe('audit'); expect(params.get('keep')).toBe('source-one');
    fireEvent.click(screen.getByRole('tab', { name: 'Team inventory and metrics' }));
    params = new URLSearchParams(screen.getByTestId('location-search').textContent ?? '');
    expect(params.get('tab')).toBe('inventory'); expect(params.get('keep')).toBe('source-one');
  });

  it('uses inventory when a tab has not been specified', async () => {
    mount('/alicloud?keep=source-one');
    expect(await screen.findByRole('tab', { name: 'Team inventory and metrics' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByTestId('inventory-panel')).toBeInTheDocument();
    expect(screen.queryByTestId('audit-panel')).not.toBeInTheDocument();
  });
});
