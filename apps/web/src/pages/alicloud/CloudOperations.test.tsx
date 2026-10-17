import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cloudApi, type CloudConfig } from '@/api/cloud';
import CloudOperations from './CloudOperations';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: () => ({ has: () => true }) }));

const meta = { source: 'live' as const, elapsedMs: 1, at: Date.now() };
const snapshot: CloudConfig = {
  name: 'alicloud-agentteams', displayName: 'AgentTeams', enabled: true, mock: false,
  environmentMock: false, version: 4, endpoint: 'https://agentteams.example.test',
  settings: { instance_id: 'instance-local' }, secretKeys: ['access_key_id'],
  operations: [{ action: 'UpdateTeam', version: '2026-06-05', method: 'POST', path: '/', read_only: false,
    parameters: [
      { name: 'InstanceId', location: 'query', schema: { type: 'string', required: true } },
      { name: 'Name', location: 'query', schema: { type: 'string', required: true } },
      { name: 'TeamMembers', location: 'query', schema: { type: 'array', required: true } },
    ] }],
};
afterEach(() => vi.restoreAllMocks());

describe('cloud operation workflow', () => {
  it('preserves provider field names and the request id when retrying an interrupted call', async () => {
    const history = vi.spyOn(cloudApi, 'history').mockResolvedValue({ data: { items: [] }, meta });
    const execute = vi.spyOn(cloudApi, 'execute').mockRejectedValueOnce(new Error('connection interrupted'))
      .mockResolvedValueOnce({ data: { id: 'run-local', requestId: 'request-local', operation: 'UpdateTeam',
        configurationVersion: 4, actor: 'admin', startedAt: '2026-09-20T10:00:00Z', status: 'uncertain',
        mocked: false, receipt: { message: 'Check provider state' } }, meta });
    const view = render(<CloudOperations snapshot={snapshot} />);
    await waitFor(() => expect(history).toHaveBeenCalledOnce());
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'team-local' } });
    fireEvent.change(screen.getByLabelText('TeamMembers (JSON)'), { target: { value: '[{"Name":"local-user"}]' } });
    const button = screen.getByRole('button', { name: '执行所选操作' });
    expect(button).toBeDisabled();
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(button);
    await screen.findByText('connection interrupted');
    fireEvent.click(button);
    await screen.findByText('UpdateTeam: uncertain');
    expect(execute).toHaveBeenCalledTimes(2);
    expect(execute.mock.calls[0][1]).toEqual(execute.mock.calls[1][1]);
    expect(execute.mock.calls[0][1]).toMatchObject({ configuration_version: 4, confirm_live: true,
      parameters: { InstanceId: 'instance-local', Name: 'team-local', TeamMembers: [{ Name: 'local-user' }] } });
    expect(button).toBeDisabled();
    view.unmount();
  });
  it('rejects invalid JSON before calling the API and labels a mock failure', async () => {
    vi.spyOn(cloudApi, 'history').mockResolvedValue({ data: { items: [] }, meta });
    const execute = vi.spyOn(cloudApi, 'execute').mockResolvedValue({ data: { id: 'mock-local', requestId: 'mock-request',
      operation: 'UpdateTeam', configurationVersion: 4, actor: 'admin', startedAt: '2026-09-20T10:00:00Z',
      status: 'failed', mocked: true, receipt: { message: 'Rejected fixture' } }, meta });
    const view = render(<CloudOperations snapshot={{ ...snapshot, mock: true }} />);
    expect(screen.queryByRole('checkbox')).toBeNull();
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'team-local' } });
    fireEvent.change(screen.getByLabelText('TeamMembers (JSON)'), { target: { value: '[invalid' } });
    const button = screen.getByRole('button', { name: '执行所选操作' });
    fireEvent.click(button);
    await screen.findByText(/JSON/ , { selector: '.ant-alert-message' });
    await waitFor(() => expect(button).not.toHaveClass('ant-btn-loading'));
    expect(execute).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('TeamMembers (JSON)'), { target: { value: '[]' } });
    fireEvent.click(button);
    await screen.findByText('UpdateTeam: failed');
    expect(screen.queryByText('UpdateTeam: succeeded')).toBeNull();
    view.unmount();
  });
});
