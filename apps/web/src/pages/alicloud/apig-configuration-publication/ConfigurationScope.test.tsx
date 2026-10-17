import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { apigConfigurationApi as api } from '@/api/apigConfigurationPublication';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import type { ApiResult } from '@/api/dataSource';
import type { ConfigurationOperation, ConfigurationState } from '@/types/apigConfigurationPublication';
import ApigConfigurationPublicationPanel from './ApigConfigurationPublicationPanel';
import { deferred, operation, operationId, preview, result, state, target } from './testFixtures';
import { installHarness, mount } from './testHarness';
import { adopt, confirm, prepare } from './testActions';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it.each(['tenant', 'session', 'tenant-roundtrip'])('drops a late original receipt and only owned URL fields after %s changes', async change => {
  window.history.replaceState({ idx: 3, key: 'retain-key', usr: { retain: true } }, '', '/alicloud?tab=apig-config&keep=user-view#guide');
  const pending = deferred<ApiResult<ConfigurationOperation>>(), receipt = vi.spyOn(api, 'receipt').mockReturnValue(pending.promise);
  mount(<ApigConfigurationPublicationPanel />); await screen.findByText(target.sourceLabel);
  fireEvent.change(screen.getByRole('textbox', { name: 'APIG configuration original request UUID' }), { target: { value: operationId } });
  fireEvent.click(screen.getByRole('button', { name: 'Read original configuration receipt (GET only)' }));
  await waitFor(() => expect(receipt).toHaveBeenCalledTimes(1)); const signal = receipt.mock.calls[0][1];
  act(() => {
    if (change === 'session') useAuthStore.setState({ sessionGeneration: 2 });
    else { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 });
      if (change === 'tenant-roundtrip') useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 3 }); }
  });
  await act(async () => { pending.resolve(result(operation())); });
  expect(signal?.aborted).toBe(true); expect(screen.queryByText('Original APIG configuration request receipt')).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'APIG configuration original request UUID' })).toHaveValue('');
  const params = new URLSearchParams(window.location.search); expect(params.has('apig_configuration_request_id')).toBe(false);
  expect(params.get('tab')).toBe('apig-config'); expect(params.get('keep')).toBe('user-view'); expect(window.location.hash).toBe('#guide');
  expect(window.history.state).toMatchObject({ idx: 3, key: 'retain-key', usr: { retain: true } });
});
it('keeps the recovery input DOM, focus and early draft when initial state GET completes', async () => {
  const pending = deferred<ApiResult<ConfigurationState>>(); vi.mocked(api.state).mockReturnValueOnce(pending.promise);
  const receipt = vi.spyOn(api, 'receipt').mockResolvedValue(result(operation())); mount(<ApigConfigurationPublicationPanel />);
  const input = screen.getByRole('textbox', { name: 'APIG configuration original request UUID' });
  fireEvent.change(input, { target: { value: operationId } }); act(() => input.focus());
  await act(async () => { pending.resolve(result(state())); }); await screen.findByText(target.sourceLabel);
  expect(input.isConnected).toBe(true); expect(screen.getByRole('textbox', { name: 'APIG configuration original request UUID' })).toBe(input);
  expect(input).toHaveValue(operationId); expect(input).toHaveFocus(); expect(receipt).not.toHaveBeenCalled();
});
it('does not render a late Apply result or old recovery UUID after A to B to A', async () => {
  const pending = deferred<ApiResult<ConfigurationOperation>>(); vi.spyOn(api, 'preview').mockResolvedValue(result(preview()));
  const applied = vi.spyOn(api, 'apply').mockReturnValue(pending.promise); mount(<ApigConfigurationPublicationPanel />);
  await adopt(); await prepare(); await confirm(); fireEvent.click(screen.getByRole('button', { name: 'Send one explicit new APIG configuration write' }));
  await waitFor(() => expect(applied).toHaveBeenCalledTimes(1)); const id = applied.mock.calls[0][0].request_id;
  act(() => { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 });
    useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 3 }); });
  await act(async () => { pending.resolve(result(operation({ requestId: id }))); });
  expect(screen.queryByText('Original APIG configuration request receipt')).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'APIG configuration original request UUID' })).toHaveValue(''); expect(applied).toHaveBeenCalledTimes(1);
});
it('aborts a previous tenant state GET and rejects its late source and observed public configuration', async () => {
  const pending = deferred<ApiResult<ConfigurationState>>(); vi.mocked(api.state).mockReturnValueOnce(pending.promise);
  mount(<ApigConfigurationPublicationPanel />); await waitFor(() => expect(api.state).toHaveBeenCalledTimes(1));
  const signal = vi.mocked(api.state).mock.calls[0][0];
  vi.mocked(api.state).mockResolvedValue(result(state({ binding: { ...target, sourceLabel: 'Current tenant source' } })));
  act(() => useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 }));
  await screen.findByText('Current tenant source'); await act(async () => { pending.resolve(result(state())); });
  expect(signal?.aborted).toBe(true); expect(screen.queryByText(target.sourceLabel)).not.toBeInTheDocument();
});
