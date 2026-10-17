import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { teamManagementApi } from '@/api/teamManagement';
import { useAuthStore } from '@/stores/authStore';
import i18n from '@/locales/i18n';
import type { Tenant } from '@/types/domain';
import type { TeamManagement, TeamPreview, TeamUserDirectory } from '@/types/teamManagement';
import TeamManagementPanel from './TeamManagementPanel';
import { directoryFixture, managementFixture, operationFixture, previewFixture } from './teamManagement/teamManagementFixtures';

const rights = new Set<string>();
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: () => ({ has: (right: string) => rights.has(right), isLoading: false, error: null }) }));
const meta = { source: 'live' as const, elapsedMs: 1, at: Date.now() };
const originalAuth = useAuthStore.getState();
const caches: QueryClient[] = [];
let data: TeamManagement;
let lastPreview: TeamPreview;
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  rights.clear(); ['alicloud:read', 'alicloud:write', 'assets:write'].forEach(right => rights.add(right));
  useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 1 });
  data = managementFixture(); lastPreview = previewFixture();
  vi.spyOn(teamManagementApi, 'list').mockImplementation(async requestId => ({ data: {
    ...data, operations: requestId ? data.operations.filter(operation => operation.requestId === requestId) : data.operations }, meta }));
  vi.spyOn(teamManagementApi, 'observeUsers').mockImplementation(async request => ({ data: {
    ...directoryFixture(), snapshotId: request.cursor ? 'directory-two' : 'directory-one',
    mocked: data.mocked === true, query: { nameLike: request.name_like ?? null },
    complete: !!request.cursor, directoryComplete: !!request.cursor && !request.name_like,
    nextCursor: request.cursor ? null : 'opaque-page-two', items: request.cursor
      ? [{ name: 'bob', displayName: null, status: null, existenceVerified: false, adminEligibility: null }]
      : directoryFixture().items }, meta }));
  vi.spyOn(teamManagementApi, 'preview').mockImplementation(async request => {
    const change = request.change;
    const memberNames = change.action === 'create' ? change.member_names : change.action === 'update' ? change.members?.names : undefined;
    lastPreview = previewFixture({ action: change.action, teamName: change.team_name, expectedStateVersion: request.expected_state_version,
      mocked: data.mocked === true, descriptionChanged: change.action !== 'delete' && change.description !== undefined,
      membersChanged: memberNames !== undefined,
      desired: { ...(change.action !== 'delete' && change.description !== undefined ? { description: change.description } : {}),
        ...(memberNames !== undefined ? { memberNames } : {}), ...(change.action === 'create' && change.admin_name ? { adminName: change.admin_name } : {}) },
      removedMembers: memberNames ? data.items[0].memberNames?.filter(name => !memberNames.includes(name)) ?? [] : [],
      ...(change.action === 'delete' ? { deleteImpact: { workerCount: 0, humanCount: 1, roomCount: 0, taskCount: 0, asyncCleanup: true } } : {}),
    });
    return { data: lastPreview, meta };
  });
  vi.spyOn(teamManagementApi, 'getPreview').mockImplementation(async () => ({ data: lastPreview, meta }));
  vi.spyOn(teamManagementApi, 'apply').mockImplementation(async request => {
    const operation = operationFixture({ requestId: request.request_id, action: lastPreview.action, teamName: lastPreview.teamName });
    data = { ...data, operations: [operation] };
    return { data: operation, meta };
  });
  vi.spyOn(teamManagementApi, 'getOperation').mockImplementation(async id => ({ data: data.operations.find(item => item.id === id)!, meta }));
  vi.spyOn(teamManagementApi, 'observe').mockImplementation(async () => ({ data: data.operations[0], meta }));
  vi.spyOn(teamManagementApi, 'publish').mockImplementation(async () => ({ data: data.operations[0], meta }));
});
afterEach(async () => {
  cleanup();
  caches.forEach(cache => cache.clear()); caches.length = 0;
  vi.restoreAllMocks(); useAuthStore.setState(originalAuth);
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});
function Location() {
  const location = useLocation();
  const navigate = useNavigate();
  return <><output data-testid="location">{location.search}</output>
    <button onClick={() => navigate('/alicloud?tab=teams&team=second-team')}>Open another inventoried team</button>
    <button onClick={() => navigate('/alicloud?tab=teams&team=existing-team')}>Open original inventoried team</button></>;
}
function mount(entry = '/alicloud?tab=teams&team=existing-team') {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } }); caches.push(cache);
  return render(<QueryClientProvider client={cache}><MemoryRouter initialEntries={[entry]}>
    <TeamManagementPanel /><Location />
  </MemoryRouter></QueryClientProvider>);
}
async function descriptionDraft() {
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Change description' }));
  fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Updated description' } });
}
async function prepare() {
  fireEvent.click(await screen.findByRole('button', { name: /Prepare change preview$/ }));
  await screen.findByText('Change preview');
}
async function apply() {
  const button = await screen.findByRole('button', { name: /Confirm change and read back$/ });
  expect(button).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox', { name: 'I reviewed the target and all differences and confirm this cloud change.' }));
  expect(button).toBeEnabled();
  await act(async () => { fireEvent.click(button); });
  await waitFor(() => expect(screen.getByRole('button', { name: /Refresh team management$/ })).toBeEnabled());
}

describe('native team management', () => {
  it('never performs cloud calls on opening and keeps read-only views usable', async () => {
    rights.delete('alicloud:write'); data = { ...data, canPrepare: false, canWrite: false };
    const operation = operationFixture({ status: 'uncertain' }); data.operations = [operation];
    mount(); await screen.findByText(/Read-only access:/);
    expect(screen.queryByRole('button', { name: 'Prepare change preview' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'View receipt' }));
    expect(screen.getByRole('button', { name: 'Refresh receipt' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Observe cloud result' })).not.toBeInTheDocument();
    expect(teamManagementApi.observeUsers).not.toHaveBeenCalled(); expect(teamManagementApi.preview).not.toHaveBeenCalled();
    expect(teamManagementApi.apply).not.toHaveBeenCalled();
  });

  it('does not fetch team management without read access', async () => {
    rights.clear(); mount(); await screen.findByText('Viewing team management requires alicloud:read.');
    expect(teamManagementApi.list).not.toHaveBeenCalled();
  });

  it('omits member replacement for description-only changes and requires separate write confirmation', async () => {
    mount(); await descriptionDraft(); await prepare();
    expect(teamManagementApi.preview).toHaveBeenCalledWith(expect.objectContaining({ expected_state_version: 3,
      configuration_version: 4, confirm_live: false, change: { action: 'update', team_name: 'existing-team', description: 'Updated description' } }));
    expect(teamManagementApi.apply).not.toHaveBeenCalled();
    await apply(); await screen.findAllByText('Verified and inventory published');
    expect(teamManagementApi.apply).toHaveBeenCalledOnce();
    expect(screen.getByTestId('location').textContent).toMatch(/request_id=[0-9a-f-]{36}/);
    expect(screen.getByText('Successful cloud receipt received')).toBeInTheDocument();
    expect(screen.getByText('Expected fields matched')).toBeInTheDocument();
    expect(screen.getByText('Complete inventory published')).toBeInTheDocument();
  });

  it('allows unknown membership to remain unchanged but cannot turn it into an empty replacement', async () => {
    data = { ...data, userDirectory: null, items: [{ ...data.items[0], memberNames: null, memberNamesAvailable: false }] };
    mount(); expect(await screen.findByRole('checkbox', { name: 'Replace the complete cloud user list' })).toBeDisabled();
    await descriptionDraft(); await prepare();
    expect(teamManagementApi.preview).toHaveBeenCalledWith(expect.objectContaining({ change: {
      action: 'update', team_name: 'existing-team', description: 'Updated description' } }));
    expect(vi.mocked(teamManagementApi.preview).mock.calls[0][0]).not.toHaveProperty('user_snapshot_id');
    expect(teamManagementApi.observeUsers).not.toHaveBeenCalled();
  });

  it('retains old members across candidate pages and requires an explicit empty replacement', async () => {
    mount(); fireEvent.click(await screen.findByRole('button', { name: 'Read next user page' }));
    await screen.findByText('bob');
    fireEvent.click(screen.getByRole('checkbox', { name: 'Replace the complete cloud user list' }));
    await prepare();
    expect(teamManagementApi.preview).toHaveBeenLastCalledWith(expect.objectContaining({ change: { action: 'update', team_name: 'existing-team',
      members: { mode: 'replace', names: ['unloaded-person'], confirm_full_replacement: true } } }));
    fireEvent.click(screen.getByRole('button', { name: 'Set expected cloud user list to empty' }));
    expect(screen.queryByText('Change preview')).not.toBeInTheDocument();
    await prepare();
    expect(teamManagementApi.preview).toHaveBeenLastCalledWith(expect.objectContaining({ change: { action: 'update', team_name: 'existing-team',
      members: { mode: 'replace', names: [], confirm_full_replacement: true } } }));
    expect(screen.getByText('Cloud users removed: unloaded-person')).toBeInTheDocument();
    expect(teamManagementApi.apply).not.toHaveBeenCalled();
  });

  it('creates with an explicitly previewed empty list and no default administrator', async () => {
    mount(); fireEvent.click(await screen.findByRole('radio', { name: 'Create team' }));
    fireEvent.change(screen.getByLabelText('Team name'), { target: { value: 'new-team' } });
    await prepare();
    expect(teamManagementApi.preview).toHaveBeenCalledWith(expect.objectContaining({ change: {
      action: 'create', team_name: 'new-team', description: '', member_names: [] } }));
    expect(screen.getAllByText(/cloud validates administrator eligibility/).length).toBeGreaterThan(0);
    expect(teamManagementApi.apply).not.toHaveBeenCalled();
    await apply(); await screen.findAllByText('Verified and inventory published');
    expect(teamManagementApi.apply).toHaveBeenCalledOnce();
  });

  it('requires an explicit Live read acknowledgement and never duplicates a busy read', async () => {
    data = { ...data, mocked: false, userDirectory: { ...directoryFixture(), mocked: false } };
    let finish!: (response: { data: TeamUserDirectory; meta: typeof meta }) => void;
    vi.mocked(teamManagementApi.observeUsers).mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    mount(); const read = await screen.findByRole('button', { name: 'Read cloud users' });
    expect(read).toBeDisabled(); fireEvent.click(screen.getByRole('checkbox', { name: 'I confirm reads against the live cloud for this instance.' }));
    fireEvent.click(read); fireEvent.click(read);
    await waitFor(() => expect(teamManagementApi.observeUsers).toHaveBeenCalledOnce());
    expect(teamManagementApi.observeUsers).toHaveBeenCalledWith(expect.objectContaining({ confirm_live: true, configuration_version: 4 }));
    await act(async () => { finish({ data: { ...directoryFixture(), mocked: false }, meta }); });
    expect(teamManagementApi.apply).not.toHaveBeenCalled();
  });

  it('retains selected members after a failed page and never treats it as an empty list', async () => {
    vi.mocked(teamManagementApi.observeUsers).mockRejectedValue(new Error('User page denied'));
    mount(); fireEvent.click(await screen.findByRole('button', { name: 'Read next user page' }));
    await screen.findByText('User page denied');
    expect(screen.getByText(/Selected cloud users: unloaded-person/)).toBeInTheDocument();
    expect(screen.getByText(/These options are stale/)).toBeInTheDocument();
    expect(teamManagementApi.apply).not.toHaveBeenCalled();
  });

  it('allows preparing and observing without assets write, but never applies or publishes', async () => {
    rights.delete('assets:write'); data.canWrite = false;
    const operation = operationFixture({ status: 'uncertain', inventoryPublish: { status: 'not_started', checkedAt: null, errorCode: null },
      allowedActions: ['read_receipt', 'observe', 'retry_inventory'] }); data.operations = [operation];
    mount(); await descriptionDraft(); await prepare();
    expect(screen.queryByRole('button', { name: 'Confirm change and read back' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'View receipt' }));
    fireEvent.click(screen.getByRole('button', { name: 'Observe cloud result' }));
    await waitFor(() => expect(teamManagementApi.observe).toHaveBeenCalledOnce());
    expect(screen.queryByRole('button', { name: 'Read inventory and publish again' })).not.toBeInTheDocument();
    expect(teamManagementApi.apply).not.toHaveBeenCalled(); expect(teamManagementApi.publish).not.toHaveBeenCalled();
  });

  it('blocks expired previews and discards confirmation when the draft changes', async () => {
    vi.mocked(teamManagementApi.preview).mockResolvedValue({ data: previewFixture({ expiresAt: new Date(Date.now() - 1000).toISOString() }), meta });
    mount(); await descriptionDraft(); await prepare();
    expect(screen.getByRole('button', { name: 'Confirm change and read back' })).toBeDisabled();
    expect(screen.getByText(/This preview cannot be submitted/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Another draft' } });
    expect(screen.queryByText('Change preview')).not.toBeInTheDocument(); expect(teamManagementApi.apply).not.toHaveBeenCalled();
  });

  it('never resends an uncertain delete and separates acceptance from cleanup and publication', async () => {
    vi.mocked(teamManagementApi.apply).mockImplementation(async request => {
      const operation = operationFixture({ requestId: request.request_id, action: 'delete', status: 'deleting',
        readback: { status: 'deleting', observedAt: new Date().toISOString(), resourceState: 'present', matchedFields: [], conflictFields: [] },
        inventoryPublish: { status: 'not_started', checkedAt: null, errorCode: null }, allowedActions: ['read_receipt', 'observe'] });
      data = { ...data, operations: [operation], items: [{ ...data.items[0], unresolvedDelete: true }] };
      return { data: operation, meta };
    });
    mount(); fireEvent.click(await screen.findByRole('radio', { name: 'Delete team' }));
    expect(screen.getByRole('button', { name: 'Prepare change preview' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Type the exact team name to delete'), { target: { value: 'existing-team' } });
    fireEvent.click(screen.getByRole('checkbox', { name: 'I understand that deleting this team starts asynchronous cleanup of associated resources.' }));
    await prepare(); await apply();
    await waitFor(() => expect(screen.getByRole('button', { name: /Prepare change preview$/ })).toBeDisabled());
    expect(screen.getAllByText('Deletion cleanup in progress').length).toBeGreaterThan(0);
    expect(screen.queryByText('Verified and inventory published')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Observe cloud result' }));
    await waitFor(() => expect(teamManagementApi.observe).toHaveBeenCalledOnce());
    expect(teamManagementApi.apply).toHaveBeenCalledOnce();
    expect(screen.queryByRole('button', { name: /retry.*(write|delete)/i })).not.toBeInTheDocument();
  });

  it('recovers a lost response by the original request ID without resending the write', async () => {
    vi.mocked(teamManagementApi.apply).mockImplementation(async request => {
      data.operations = [operationFixture({ requestId: request.request_id, status: 'uncertain' })];
      throw new Error('Write response disconnected');
    });
    mount(); await descriptionDraft(); await prepare(); await apply();
    await screen.findByText('Write response disconnected');
    fireEvent.click(screen.getByRole('button', { name: 'Recover operation by request ID' }));
    await screen.findAllByText('Result uncertain');
    expect(screen.getByText('operation-one')).toBeInTheDocument();
    expect(teamManagementApi.list).toHaveBeenLastCalledWith(vi.mocked(teamManagementApi.apply).mock.calls[0][0].request_id);
    expect(teamManagementApi.apply).toHaveBeenCalledOnce();
  });

  it('restores an operation from the URL and keeps partial publication distinct', async () => {
    const operation = operationFixture({ status: 'uncertain', allowedActions: ['read_receipt', 'retry_inventory'],
      inventoryPublish: { status: 'failed', checkedAt: null, errorCode: 'inventory_read_failed' } }); data.operations = [operation];
    mount(`/alicloud?tab=teams&request_id=${operation.requestId}`);
    await screen.findByText('Publication failed');
    expect(screen.getByText('Successful cloud receipt received')).toBeInTheDocument();
    expect(screen.queryByText('Verified and inventory published')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Read inventory and publish again' }));
    await waitFor(() => expect(teamManagementApi.publish).toHaveBeenCalledOnce());
    expect(teamManagementApi.apply).not.toHaveBeenCalled();
  });

  it('uses only server-confirmed recovery configuration without making the old preview writable', async () => {
    data.configurationVersion = 5;
    const operation = operationFixture({ status: 'uncertain', recoveryConfigurationVersion: 5,
      allowedActions: ['read_receipt', 'observe', 'retry_inventory'],
      inventoryPublish: { status: 'failed', checkedAt: null, errorCode: 'inventory_read_failed' } });
    data.operations = [operation];
    mount(`/alicloud?tab=teams&request_id=${operation.requestId}`);
    await screen.findByText('Server-confirmed recovery scope / configuration: scope-one / 5');
    expect(screen.getByText('scope-one / 4')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Observe cloud result' }));
    await waitFor(() => expect(teamManagementApi.observe).toHaveBeenCalledWith(operation.id,
      expect.objectContaining({ configuration_version: 5, confirm_live: false })));
    await waitFor(() => expect(screen.getByRole('button', { name: /Refresh team management$/ })).toBeEnabled());
    const publish = await screen.findByRole('button', { name: /Read inventory and publish again$/ });
    await waitFor(() => expect(publish).toBeEnabled());
    fireEvent.click(publish);
    await waitFor(() => expect(teamManagementApi.publish).toHaveBeenCalledWith(operation.id,
      expect.objectContaining({ configuration_version: 5 })));
    await waitFor(() => expect(screen.getByRole('button', { name: /Refresh team management$/ })).toBeEnabled());
    await descriptionDraft(); await prepare();
    // The mocked old preview remains bound to configuration 4, so recovery never authorizes this old write.
    expect(screen.getByRole('button', { name: 'Confirm change and read back' })).toBeDisabled();
    expect(teamManagementApi.apply).not.toHaveBeenCalled();
  });

  it('keeps cross-account historical receipts read-only even when the browser still has write permission', async () => {
    data.scopeId = 'different-account-scope'; data.configurationVersion = 5;
    const operation = operationFixture({ status: 'superseded', recoveryScopeId: null,
      recoveryConfigurationVersion: null, allowedActions: ['read_receipt'] });
    data.operations = [operation]; mount(`/alicloud?tab=teams&request_id=${operation.requestId}`);
    await screen.findByText('This is a historical scope or configuration. Its receipt is preserved, but it cannot be applied to the current instance.');
    expect(screen.getByRole('button', { name: 'Refresh receipt' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Observe cloud result' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Read inventory and publish again' })).not.toBeInTheDocument();
    expect(teamManagementApi.observe).not.toHaveBeenCalled(); expect(teamManagementApi.publish).not.toHaveBeenCalled();
    expect(teamManagementApi.apply).not.toHaveBeenCalled();
  });

  it('discards confirmation and ignores a late user page after switching organizations', async () => {
    let finish!: (response: { data: TeamUserDirectory; meta: typeof meta }) => void;
    vi.mocked(teamManagementApi.observeUsers).mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    mount(); fireEvent.click(await screen.findByRole('button', { name: 'Read cloud users' }));
    await waitFor(() => expect(teamManagementApi.observeUsers).toHaveBeenCalledOnce());
    data = { ...data, scopeId: 'scope-two', items: [], userDirectory: null };
    act(() => useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 }));
    await waitFor(() => expect(screen.getByLabelText('Team name')).toHaveValue(''));
    await act(async () => { finish({ data: directoryFixture(), meta }); });
    expect(screen.queryByText('alice')).not.toBeInTheDocument();
    expect(screen.queryByText('Change preview')).not.toBeInTheDocument(); expect(teamManagementApi.apply).not.toHaveBeenCalled();
  });

  it('follows another inventory team in a retained tab and hides its previous delayed preview', async () => {
    data.items.push({ ...data.items[0], teamName: 'second-team', description: 'Second team description', memberNames: ['second-member'] });
    let finish!: (response: { data: TeamPreview; meta: typeof meta }) => void;
    vi.mocked(teamManagementApi.preview).mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    mount(); await descriptionDraft();
    fireEvent.click(screen.getByRole('button', { name: 'Prepare change preview' }));
    await waitFor(() => expect(teamManagementApi.preview).toHaveBeenCalledOnce());
    fireEvent.click(screen.getByRole('button', { name: 'Open another inventoried team' }));
    expect(screen.getByLabelText('Team name')).toHaveValue('second-team');
    expect(screen.getByLabelText('Description')).toHaveValue('Second team description');
    expect(screen.getByText('Selected cloud users: second-member')).toBeInTheDocument();
    await act(async () => { finish({ data: previewFixture(), meta }); });
    expect(screen.queryByText('Change preview')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Confirm change and read back' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Open original inventoried team' }));
    expect(screen.getByLabelText('Team name')).toHaveValue('existing-team');
    expect(screen.getByLabelText('Description')).toHaveValue('Updated description');
    expect(screen.queryByText('Change preview')).not.toBeInTheDocument();
    expect(teamManagementApi.apply).not.toHaveBeenCalled();
  });

  it('presents the same operation guide and strict membership meaning in Chinese', async () => {
    await i18n.changeLanguage('zh-CN'); mount();
    fireEvent.click(await screen.findByText('团队维护操作指南'));
    expect(await screen.findByText(/单独修改描述会保持名单/)).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: '替换完整云人员名单' })).not.toBeChecked();
    expect(teamManagementApi.apply).not.toHaveBeenCalled();
  });
});
