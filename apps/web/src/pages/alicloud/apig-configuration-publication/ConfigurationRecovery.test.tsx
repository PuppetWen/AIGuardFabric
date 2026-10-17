import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { apigConfigurationApi as api } from '@/api/apigConfigurationPublication';
import type { ApiResult } from '@/api/dataSource';
import type { ConfigurationOperation } from '@/types/apigConfigurationPublication';
import { ApiRequestError } from '@/api/transport';
import ApigConfigurationPublicationPanel from './ApigConfigurationPublicationPanel';
import { deferred, historicalId, operation, operationId, preview, result, state } from './testFixtures';
import { installHarness, mount } from './testHarness';
import { adopt, confirm, prepare, read } from './testActions';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

async function submit() { await adopt(); await prepare(); await confirm(); fireEvent.click(screen.getByRole('button', { name: 'Send one explicit new APIG configuration write' })); }
it.each([0, 500])('an ambiguous Apply status %s and original 404 retain the immutable intent; historical complete B cannot unlock A', async status => {
  vi.spyOn(api, 'preview').mockResolvedValue(result(preview()));
  const applied = vi.spyOn(api, 'apply').mockRejectedValue(new ApiRequestError('Response unavailable', status, 'network', false));
  const receipt = vi.spyOn(api, 'receipt').mockRejectedValue(new ApiRequestError('Original not found', 404, 'not_found', false));
  mount(<ApigConfigurationPublicationPanel />); await submit(); await screen.findByText('Response unavailable');
  const id = applied.mock.calls[0][0].request_id;
  expect(screen.getByRole('textbox', { name: 'APIG configuration original request UUID' })).toHaveValue(id);
  fireEvent.click(screen.getByRole('button', { name: 'Read the retained current intent receipt' })); await screen.findByText('Original not found');
  expect(receipt).toHaveBeenCalledWith(id, expect.any(AbortSignal));
  receipt.mockResolvedValue(result(operation({ requestId: historicalId }))); await read(historicalId);
  expect(screen.getByRole('button', { name: 'Original intent completed or explicitly rejected; explicitly prepare a new intent' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Prepare APIG configuration preview' })).toBeDisabled(); expect(applied).toHaveBeenCalledTimes(1);
  receipt.mockResolvedValue(result(operation({ requestId: id }))); fireEvent.click(screen.getByRole('button', { name: 'Read the retained current intent receipt' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Original intent completed or explicitly rejected; explicitly prepare a new intent' })).toBeEnabled());
  expect(applied).toHaveBeenCalledTimes(1);
});
it('an invalid successful response also retains its UUID and prevents a second submission', async () => {
  vi.spyOn(api, 'preview').mockResolvedValue(result(preview()));
  const applied = vi.spyOn(api, 'apply').mockResolvedValue(result({} as unknown as ConfigurationOperation));
  mount(<ApigConfigurationPublicationPanel />); await submit();
  await screen.findByText(/Invalid original receipt; keep the original intent locked/);
  expect(screen.getByRole('textbox', { name: 'APIG configuration original request UUID' })).toHaveValue(applied.mock.calls[0][0].request_id);
  expect(screen.getByRole('button', { name: 'Send one explicit new APIG configuration write' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Original intent completed or explicitly rejected; explicitly prepare a new intent' })).toBeDisabled();
  expect(applied).toHaveBeenCalledTimes(1);
});
it('allows an explicit original GET during Apply and does not let a late response override its outcome', async () => {
  const pending = deferred<ApiResult<ConfigurationOperation>>(); vi.spyOn(api, 'preview').mockResolvedValue(result(preview()));
  const applied = vi.spyOn(api, 'apply').mockReturnValue(pending.promise);
  const receipt = vi.spyOn(api, 'receipt').mockImplementation(async id => result(operation({ requestId: id, status: 'uncertain',
    completionState: 'running', localPublication: { status: 'not_staged' }, cloudWrite: { status: 'unknown', providerRequestId: null }, allowedActions: ['read_receipt'] })));
  mount(<ApigConfigurationPublicationPanel />); await submit(); await waitFor(() => expect(applied).toHaveBeenCalledTimes(1));
  const id = applied.mock.calls[0][0].request_id;
  fireEvent.click(screen.getByRole('button', { name: 'Read the retained current intent receipt' })); await screen.findByText('unknown / —');
  await act(async () => { pending.resolve(result(operation({ requestId: id }))); });
  expect(receipt).toHaveBeenCalledWith(id, expect.any(AbortSignal)); expect(screen.getByText('unknown / —')).toBeInTheDocument();
  expect(screen.queryByText('accepted / actual-provider-ack')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Original intent completed or explicitly rejected; explicitly prepare a new intent' })).toBeDisabled();
});
it('recovers a disabled configuration receipt with empty local-only input and no provider observation', async () => {
  const pending = operation({ status: 'uncertain', finishedAt: null, completionState: 'pending_audit', localPublication: { status: 'pending_audit' },
    sourceCurrent: false, recoveryScopeId: null, recoveryConfigurationVersion: null, allowedActions: ['read_receipt', 'recover_local'] });
  vi.mocked(api.state).mockResolvedValue(result(state({ enabled: false, binding: null, observation: null, canPrepare: false, canApply: false, canObserve: false, canInitializeMockFixture: false })));
  vi.spyOn(api, 'receipt').mockResolvedValue(result(pending)); const recovered = vi.spyOn(api, 'recover').mockResolvedValue(result(operation()));
  const observed = vi.spyOn(api, 'observeOriginal'); mount(<ApigConfigurationPublicationPanel />); await read(operationId);
  expect(screen.getByText(/Unknown or incomplete local audit is not success/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Explicitly recover the local configuration receipt' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Confirm local-only recovery' }));
  await waitFor(() => expect(recovered).toHaveBeenCalledWith(operationId)); expect(observed).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: /Explicitly observe the original configuration target/ })).toBeDisabled();
});
it('clipboard failure is visible and never substitutes an API action', async () => {
  const originalNavigator = navigator;
  const clipboard = Object.getOwnPropertyDescriptor(originalNavigator, 'clipboard');
  const writeText = vi.fn().mockRejectedValue(new Error('Denied'));
  Object.defineProperty(originalNavigator, 'clipboard', { value: { writeText }, configurable: true });
  try {
    vi.spyOn(api, 'receipt').mockResolvedValue(result(operation())); const applied = vi.spyOn(api, 'apply');
    mount(<ApigConfigurationPublicationPanel />); await read(operationId); fireEvent.click(screen.getByRole('button', { name: 'Copy original configuration request UUID' }));
    await screen.findByText('Copy failed; select the displayed UUID manually.'); expect(writeText).toHaveBeenCalledWith(operationId); expect(applied).not.toHaveBeenCalled();
    expect(navigator).toBe(originalNavigator);
    expect(typeof navigator.userAgent).toBe('string');
  } finally {
    if (clipboard) Object.defineProperty(originalNavigator, 'clipboard', clipboard);
    else Reflect.deleteProperty(originalNavigator, 'clipboard');
  }
});
