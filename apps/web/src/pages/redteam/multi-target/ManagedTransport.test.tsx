import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ConfigProvider } from 'antd';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { multiTargetApi, type ManagedView, type MultiProfile } from '@/api/redteamMultiTarget';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import { ManagedTransport } from './ManagedTransport';
const original = useAuthStore.getState();
const id = '10000000-0000-4000-8000-000000000001';
const profile: MultiProfile = { id, assetId: id, name: 'Managed MCP', enabled: true, version: 7 };
const value: ManagedView = { configured: false, profileId: id, profileVersion: 7, url: 'http://10.2.3.4:8080/mcp', version: 0, settings: null };
beforeEach(() => {
  useAuthStore.setState({ tenant: { id: 'a', slug: 'a' } as Tenant, sessionGeneration: 1 });
  vi.spyOn(multiTargetApi, 'managed').mockResolvedValue(value);
  vi.spyOn(multiTargetApi, 'saveManaged').mockImplementation(async (kind, profileId, input) => ({ kind, profileId, profileVersion: input.profile_version,
    version: input.expected_version + 1, url: input.url, enabled: input.enabled, mcpProtocolRevision: input.mcp_protocol_revision,
    privateNetwork: input.private_network ? { addresses: input.private_network.addresses, port: input.private_network.port, allowPlainHttp: input.private_network.allow_plain_http } : null }));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); useAuthStore.setState(original); });
async function mount() {
  render(<ConfigProvider theme={{ token: { motion: false } }}><ManagedTransport agents={[]} mcps={[profile]} zh={false} /></ConfigProvider>);
  expect(multiTargetApi.managed).not.toHaveBeenCalled();
  fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Managed target profile' }));
  fireEvent.click(await screen.findByText('Managed MCP · v7 · ' + id));
  fireEvent.click(screen.getByRole('button', { name: 'Read current transport settings' }));
  await screen.findByText(/profile v7 · CAS v0/);
}
it('no default approval and actual manual HTTP private consent produce exact CAS/profile/URL input', async () => {
  await mount();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Explicitly approve private network' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Exact private addresses' }), { target: { value: '10.2.3.4' } });
  fireEvent.click(screen.getByRole('checkbox', { name: 'I explicitly permit plain HTTP on this approved private address/port' }));
  fireEvent.click(screen.getByRole('checkbox', { name: 'I reviewed this exact URL/version, protocol and network' }));
  fireEvent.click(screen.getByRole('button', { name: 'Save reviewed approval' }));
  await waitFor(() => expect(multiTargetApi.saveManaged).toHaveBeenCalledWith('mcp-http', id, {
    expected_version: 0, profile_version: 7, url: value.url, enabled: true, mcp_protocol_revision: '2026-07-28',
    private_network: { addresses: ['10.2.3.4'], port: 8080, allow_plain_http: true, confirm_exact_private_network: true },
  }, expect.any(AbortSignal)));
});
it('409 preserves draft and baseline; compare GET does not adopt or dispatch', async () => {
  await mount(); vi.mocked(multiTargetApi.saveManaged).mockRejectedValue(new Error('409'));
  fireEvent.click(screen.getByRole('checkbox', { name: 'I reviewed this exact URL/version, protocol and network' }));
  fireEvent.click(screen.getByRole('button', { name: 'Save reviewed approval' }));
  await screen.findByText(/Draft and reviewed CAS version retained/);
  vi.mocked(multiTargetApi.managed).mockResolvedValue({ ...value, version: 4 });
  fireEvent.click(screen.getByRole('button', { name: 'Compare latest settings' }));
  await screen.findByRole('button', { name: 'Explicitly adopt latest settings' });
  expect(screen.getByText(/profile v7 · CAS v0/)).toBeInTheDocument(); expect(multiTargetApi.saveManaged).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Explicitly adopt latest settings' }));
  await screen.findByText(/profile v7 · CAS v4/); expect(multiTargetApi.saveManaged).toHaveBeenCalledTimes(1);
});
it('a late settings response across session change cannot populate approval or issue PUT', async () => {
  let resolve!: (value: ManagedView) => void; const pending = new Promise<ManagedView>(done => { resolve = done; });
  vi.mocked(multiTargetApi.managed).mockReturnValue(pending);
  render(<ConfigProvider theme={{ token: { motion: false } }}><ManagedTransport agents={[]} mcps={[profile]} zh={false} /></ConfigProvider>);
  fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Managed target profile' })); fireEvent.click(await screen.findByText('Managed MCP · v7 · ' + id));
  fireEvent.click(screen.getByRole('button', { name: 'Read current transport settings' }));
  const signal = vi.mocked(multiTargetApi.managed).mock.calls[0][2];
  act(() => useAuthStore.setState({ sessionGeneration: 2 }));
  await act(async () => { resolve(value); await pending; });
  expect(signal?.aborted).toBe(true); expect(screen.queryByText(/profile v7 · CAS/)).not.toBeInTheDocument();
  expect(multiTargetApi.saveManaged).not.toHaveBeenCalled();
});
