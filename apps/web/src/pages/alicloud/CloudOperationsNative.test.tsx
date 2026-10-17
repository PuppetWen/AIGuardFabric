import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { cloudApi, type CloudConfig } from '@/api/cloud';
import i18n from '@/locales/i18n';
import CloudOperations from './CloudOperations';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: () => ({ has: () => true }) }));

afterEach(async () => { vi.restoreAllMocks(); await act(async () => { await i18n.changeLanguage('zh-CN'); }); });

it('routes native team writes to the preview workflow and cannot run their raw parameters', async () => {
  await i18n.changeLanguage('en-US');
  vi.spyOn(cloudApi, 'history').mockResolvedValue({ data: { items: [] }, meta: { source: 'live', at: Date.now(), elapsedMs: 1 } });
  const execute = vi.spyOn(cloudApi, 'execute');
  const snapshot: CloudConfig = { name: 'agentteams', displayName: 'AgentTeams', enabled: true, mock: true,
    environmentMock: false, version: 4, endpoint: 'https://agentteams.example.test', settings: {}, secretKeys: [],
    operations: ['CreateTeam', 'UpdateTeam', 'DeleteTeam'].map(action => ({ action, version: '2026-06-05',
      method: 'POST', path: '/', read_only: false, parameters: [{ name: 'Name', location: 'query', schema: { type: 'string' } }] })),
  };
  await act(async () => { render(<CloudOperations snapshot={snapshot} />); });
  expect(screen.getByRole('link', { name: 'Open Team management' })).toHaveAttribute('href', '/alicloud?tab=teams');
  const run = screen.getByRole('button', { name: 'Run selected operation' });
  expect(run).toBeDisabled(); fireEvent.click(run);
  expect(screen.queryByLabelText('Name')).not.toBeInTheDocument(); expect(execute).not.toHaveBeenCalled();
});
