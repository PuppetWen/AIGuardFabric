import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ConfigProvider } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { taskHandlingApi } from '@/api/agentTeamsTaskHandling';
import { useSessionAccess } from '@/api/sessionAccess';
import i18n from '@/locales/i18n';
import TaskHandlingPanel from './TaskHandlingPanel';
import { event, page, receipt, result } from './testFixtures';

vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
vi.mock('../AgentTeamsTracePanel', () => ({ default: () => <div>Actual trace panel</div> }));
const rights = new Set<string>();
beforeEach(async () => {
  await i18n.changeLanguage('en-US'); rights.clear();
  ['alicloud:read', 'sources:read', 'alicloud:write', 'sources:write'].forEach(value => rights.add(value));
  vi.mocked(useSessionAccess).mockImplementation(() => ({ has: (permission: string) => rights.has(permission), isLoading: false }) as ReturnType<typeof useSessionAccess>);
  vi.spyOn(taskHandlingApi, 'list').mockResolvedValue(result(page()));
  vi.spyOn(taskHandlingApi, 'event').mockResolvedValue(result(event()));
  vi.spyOn(taskHandlingApi, 'resolve').mockResolvedValue(result(receipt()));
  vi.spyOn(taskHandlingApi, 'archive').mockResolvedValue(result(receipt({ purpose: 'operator-archive' })));
  vi.spyOn(taskHandlingApi, 'request').mockResolvedValue(result(receipt()));
});
afterEach(async () => { cleanup(); vi.restoreAllMocks(); await act(async () => { await i18n.changeLanguage('zh-CN'); }); });
function mount() { return render(<MemoryRouter><ConfigProvider theme={{ token: { motion: false } }}><TaskHandlingPanel /></ConfigProvider></MemoryRouter>); }
async function inspect() {
  fireEvent.click(screen.getByRole('button', { name: 'Read / refresh list' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Inspect and handle' }));
  await screen.findByText('Original event ID');
}

it('shows useful guidance and received-error limits without fetching or dispatching on mount', async () => {
  mount(); expect(taskHandlingApi.list).not.toHaveBeenCalled(); expect(taskHandlingApi.resolve).not.toHaveBeenCalled();
  expect(screen.getByText(/An observation|A reported error is an observation/)).toBeInTheDocument();
  fireEvent.click(screen.getByText('How to use'));
  expect(await screen.findByText(/Bind the audit source/)).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Replay/ })).not.toBeInTheDocument();
});

it('requires both read permissions and makes no requests for an unprivileged viewer', () => {
  rights.delete('sources:read'); mount();
  expect(screen.getByText('Viewing requires alicloud:read and sources:read.')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Read / refresh list' })).not.toBeInTheDocument();
  expect(taskHandlingApi.list).not.toHaveBeenCalled();
});

it('shows safe task evidence to a reader while disabling all operator writes', async () => {
  rights.delete('sources:write'); mount(); await inspect();
  expect(screen.getAllByText('Worker reported a task error').length).toBeGreaterThan(0);
  expect(screen.getByText('worker-one')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Save operator decision' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Archive local record' })).toBeDisabled();
  expect(taskHandlingApi.resolve).not.toHaveBeenCalled(); expect(taskHandlingApi.archive).not.toHaveBeenCalled();
});

it('allows disabled-source annotation but only archive when the source has been removed', async () => {
  vi.mocked(taskHandlingApi.event).mockResolvedValue(result(event({ currentSource: { ...event().currentSource, sourceEnabled: false } })));
  mount(); await inspect();
  expect(screen.getByText('Disabled; operator annotations remain available')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Save operator decision' })).toBeEnabled();
  vi.mocked(taskHandlingApi.event).mockResolvedValue(result(event({ allowedActions: ['read', 'archive'],
    currentSource: { ...event().currentSource, sourceGone: true, sourceExists: false, fingerprint: null, cloudConfigurationVersion: null } })));
  fireEvent.click(screen.getByRole('button', { name: 'Read latest detail' }));
  await screen.findByText('Source removed; archive existing records only');
  expect(screen.getByRole('button', { name: 'Save operator decision' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Archive local record' })).toBeEnabled();
});

it('warns about a truncated evidence window and never invents a complete failure count', async () => {
  vi.mocked(taskHandlingApi.list).mockResolvedValue(result(page({ total: 2000, truncated: true })));
  mount(); fireEvent.click(screen.getByRole('button', { name: 'Read / refresh list' }));
  expect(await screen.findByText('The 2,000-record evidence limit was reached. This list is not a complete error inventory.')).toBeInTheDocument();
  expect(screen.getByText('Observations in this window: 2000')).toBeInTheDocument();
});
