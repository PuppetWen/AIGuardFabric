import { fireEvent, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import { cloudApi } from '@/api/cloud';
import AliCloudPage from '@/pages/AliCloudPage';
import CloudOperations from '../CloudOperations';
import CloudEditor from '../CloudEditor';
import { config, result } from './testFixtures';
import { installHarness, mount } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
vi.mock('@/api/client', () => ({ api: {}, useApiQuery: () => ({ data: { data: [] }, isLoading: false, error: null, refetch: vi.fn() }) }));
vi.mock('../CloudConnections', () => ({ default: () => null }));
vi.mock('../AgentTeamsAuditPanel', () => ({ default: () => <div>Read-only audit panel</div> }));
vi.mock('../TeamTable', () => ({ TeamTable: () => null }));
vi.mock('../CrossCallsPanel', () => ({ CrossCallsPanel: () => null }));
vi.mock('../BindingsPanel', () => ({ BindingsPanel: () => null }));
vi.mock('../SelfCheckPanel', () => ({ SelfCheckPanel: () => null }));
installHarness();
function LocationProbe() { return <output aria-label="Current tab parameters">{useLocation().search}</output>; }

it('opens the native APIG deep link and preserves its receipt and other query parameters across tabs', async () => {
  mount(<MemoryRouter initialEntries={['/alicloud?tab=apig-policy&apig_request_id=owned-receipt&keep=user-view']}><AliCloudPage /><LocationProbe /></MemoryRouter>);
  expect(await screen.findByRole('tab', { name: 'APIG policy publication' })).toHaveAttribute('aria-selected', 'true');
  expect(screen.getByText('APIG independent rate-limit policy publication')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('tab', { name: 'Messages and call audit' })); await screen.findByText('Read-only audit panel');
  const params = new URLSearchParams(screen.getByLabelText('Current tab parameters').textContent ?? '');
  expect(params.get('tab')).toBe('audit'); expect(params.get('apig_request_id')).toBe('owned-receipt'); expect(params.get('keep')).toBe('user-view');
});
it('routes UpdatePolicy to native publication without offering the generic write executor', async () => {
  const execute = vi.spyOn(cloudApi, 'execute'); vi.spyOn(cloudApi, 'history').mockResolvedValue(result({ items: [] }));
  const snapshot = { ...config(), operations: [{ action: 'UpdatePolicy', version: '2024-03-27', method: 'PUT', path: '/policies/id', read_only: false, parameters: [] }] };
  mount(<CloudOperations snapshot={snapshot} />); await screen.findByText(/UpdatePolicy uses dedicated APIG publication/);
  expect(screen.getByRole('link', { name: 'Open five-ID binding, trusted previews and original receipts' })).toHaveAttribute('href', '/alicloud?tab=apig-policy');
  expect(screen.getByRole('button', { name: 'Run selected operation' })).toBeDisabled(); expect(execute).not.toHaveBeenCalled();
});
it('retains consent on unchanged metadata save, then clears it on credential rotation while preserving IDs and unrelated settings', async () => {
  const snapshot = config();
  vi.spyOn(cloudApi, 'configuration').mockResolvedValue(result(snapshot)); const save = vi.spyOn(cloudApi, 'save').mockRejectedValue(new Error('Keep draft for review'));
  mount(<CloudEditor name="alicloud-apig" onClose={vi.fn()} onSaved={vi.fn()} />);
  const secret = await screen.findByLabelText('AccessKey ID', { selector: 'input[type="password"]' });
  fireEvent.click(screen.getByRole('button', { name: /Save configuration$/ })); await screen.findByText('Keep draft for review');
  expect(save).toHaveBeenCalledWith('alicloud-apig', expect.objectContaining({ settings: expect.objectContaining({ managed_policy_confirmed: true }) }));
  fireEvent.change(secret, { target: { value: 'synthetic-rotated-key' } });
  await waitFor(() => expect(screen.getByRole('button', { name: /Save configuration$/ })).not.toHaveClass('ant-btn-loading'));
  fireEvent.click(screen.getByRole('button', { name: /Save configuration$/ })); await screen.findByText('Keep draft for review');
  await waitFor(() => expect(save).toHaveBeenCalledTimes(2)); expect(save).toHaveBeenLastCalledWith('alicloud-apig', expect.objectContaining({ expected_version: 1,
    settings: expect.objectContaining({ managed_policy_confirmed: false, policy_id: 'policy-agf-demo', policy_http_api_id: 'api-agf-demo', custom_preserved: 'user-owned-value' }),
    secrets: expect.objectContaining({ access_key_id: 'synthetic-rotated-key' }) }));
  expect(screen.getByRole('link', { name: /Open dedicated APIG publication in a new tab/ })).toHaveAttribute('href', '/alicloud?tab=apig-policy');
});
