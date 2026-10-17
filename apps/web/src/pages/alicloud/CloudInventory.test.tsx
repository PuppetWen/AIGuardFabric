import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { cloudApi, type CloudConfig } from '@/api/cloud';
import i18n from '@/locales/i18n';
import { CloudInventory } from './CloudInventory';

const snapshot: CloudConfig = {
  name: 'alicloud-agentteams', displayName: 'AgentTeams', enabled: true, mock: false,
  environmentMock: false, version: 4, endpoint: 'https://agentteams.example.test',
  settings: { instance_id: 'instance-local' }, secretKeys: [], operations: [],
};
const success = (mocked: boolean) => ({ data: { mocked, teams: 2, workers: 3, assets: 3, tasks: 4, note: 'Complete' },
  meta: { source: 'live' as const, elapsedMs: 1, at: Date.now() } });
type SyncResponse = Awaited<ReturnType<typeof cloudApi.syncTeams>>;

function mount(config: CloudConfig) {
  const client = new QueryClient();
  render(<QueryClientProvider client={client}><CloudInventory snapshot={config} /></QueryClientProvider>);
  return client;
}

afterEach(async () => {
  cleanup();
  vi.restoreAllMocks();
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});

it('requires live confirmation and uses a new complete-read request only when the user retries a failed inventory', async () => {
  await i18n.changeLanguage('en-US');
  let rejectFirst: (reason: Error) => void = () => { throw new Error('Pending request was not initialized'); };
  const pending = new Promise<SyncResponse>((_, reject) => { rejectFirst = reject; });
  const sync = vi.spyOn(cloudApi, 'syncTeams').mockReturnValueOnce(pending).mockResolvedValueOnce(success(false));
  const client = mount(snapshot);
  const refresh = vi.spyOn(client, 'invalidateQueries');
  const button = screen.getByRole('button', { name: 'Read complete inventory and synchronize' });
  expect(button).toBeDisabled();
  fireEvent.click(button);
  expect(sync).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm cloud reads and local inventory updates' }));
  fireEvent.click(button);
  fireEvent.click(button);
  expect(sync).toHaveBeenCalledTimes(1);
  expect(button).toBeDisabled();
  expect(screen.getByRole('checkbox')).toBeDisabled();

  await act(async () => { rejectFirst(new Error('Worker instance mismatch')); });
  expect(await screen.findByText('Error: Worker instance mismatch')).toBeInTheDocument();
  expect(screen.getByText(/A new request ID reads the complete lists again/)).toBeInTheDocument();
  expect(button).toBeEnabled();
  expect(sync).toHaveBeenCalledTimes(1);
  expect(refresh).not.toHaveBeenCalled();
  fireEvent.click(button);
  expect(await screen.findByText('Live · Teams 2 · Worker 3 · Assets 3 · Tasks 4')).toBeInTheDocument();
  await waitFor(() => expect(button).toBeEnabled());
  expect(sync).toHaveBeenCalledTimes(2);
  const first = sync.mock.calls[0][0] as { request_id: string };
  const second = sync.mock.calls[1][0] as { request_id: string };
  expect(first.request_id).toMatch(/^[0-9a-f-]{36}$/);
  expect(second.request_id).not.toBe(first.request_id);
  expect(second).toMatchObject({ configuration_version: 4, confirm_live: true });
  expect(refresh).toHaveBeenCalledOnce();
  expect(screen.queryByText('Error: Worker instance mismatch')).not.toBeInTheDocument();
  client.clear();
});

it('clears an earlier successful summary when a later user-started mock inventory fails', async () => {
  await i18n.changeLanguage('en-US');
  const sync = vi.spyOn(cloudApi, 'syncTeams').mockResolvedValueOnce(success(true))
    .mockRejectedValueOnce(new Error('Incomplete page'));
  const client = mount({ ...snapshot, mock: true });
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  const button = screen.getByRole('button', { name: 'Read complete inventory and synchronize' });
  fireEvent.click(button);
  expect(await screen.findByText('Mock · Teams 2 · Worker 3 · Assets 3 · Tasks 4')).toBeInTheDocument();
  await waitFor(() => expect(button).toBeEnabled());
  fireEvent.click(button);
  expect(await screen.findByText('Error: Incomplete page')).toBeInTheDocument();
  expect(screen.queryByText('Mock · Teams 2 · Worker 3 · Assets 3 · Tasks 4')).not.toBeInTheDocument();
  expect(sync).toHaveBeenCalledTimes(2);
  client.clear();
});
