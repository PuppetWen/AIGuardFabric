import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { ApiRequestError } from '@/api/transport';
import type { ApiResult } from '@/api/dataSource';
import { agentteamsOrchestrationApi as api } from '@/api/agentteamsOrchestration';
import OrchestrationPanel from './OrchestrationPanel';
import type { Receipt } from './types';
import { deferred, receipt, result } from './testFixtures';
import { installHarness, mount } from './testHarness';
import { apply, prepare, selectTeam } from './testInteractions';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();
const read = () => screen.getByRole('button', { name: /Read the original receipt \(GET, no repeat sync\)/ });
const newAction = () => screen.getByRole('button', { name: 'Start a new action explicitly (keep draft baseline)' });

it.each([0, 408, 503, 'invalid-2xx'] as const)('retains one frozen intent and prevents another PUT after %s', async outcome => {
  if (outcome === 'invalid-2xx') vi.mocked(api.apply).mockImplementation(async (_team, body) => result(receipt(body, { version: 0 })));
  else vi.mocked(api.apply).mockRejectedValue(new ApiRequestError('Outcome unknown', outcome, 'unknown', false));
  mount(<OrchestrationPanel />); await selectTeam(); await prepare(); await apply();
  await screen.findByText('Original request state: unknown'); const body = vi.mocked(api.apply).mock.calls[0][1];
  expect(screen.getByRole('textbox', { name: 'Original orchestration request UUID' })).toHaveValue(body.request_id);
  expect(screen.getByRole('textbox', { name: 'Original orchestration request UUID' })).toBeDisabled();
  expect(newAction()).toBeDisabled(); expect(screen.getByRole('button', { name: 'Commit the reviewed candidate' })).toBeDisabled();
  fireEvent.doubleClick(screen.getByRole('button', { name: 'Commit the reviewed candidate' }));
  fireEvent.click(screen.getByRole('button', { name: /Reload current state to compare/ }));
  await waitFor(() => expect(api.state).toHaveBeenCalledTimes(2));
  expect(api.apply).toHaveBeenCalledTimes(1); expect(vi.mocked(api.apply).mock.calls[0][1]).toBe(body);
  expect(screen.getByRole('button', { name: 'Adopt the read baseline explicitly (no save)' })).toBeDisabled();
});

it('a receipt 404 never unlocks; a later original fact requires explicit new action without silently adopting its revision', async () => {
  vi.mocked(api.apply).mockRejectedValue(new ApiRequestError('Reply lost', 0, 'network', false));
  vi.mocked(api.receipt).mockRejectedValueOnce(new ApiRequestError('Original receipt not found', 404, 'not_found', false))
    .mockImplementation(async request => result(receipt(vi.mocked(api.apply).mock.calls[0][1], { requestId: request })));
  mount(<OrchestrationPanel />); await selectTeam(); await prepare(); await apply();
  fireEvent.click(read()); await screen.findByText('Original receipt not found'); expect(newAction()).toBeDisabled();
  expect(api.apply).toHaveBeenCalledTimes(1); fireEvent.click(read()); await screen.findByText('Immutable original receipt');
  await waitFor(() => expect(newAction()).toBeEnabled()); expect(screen.getByText(/Draft baseline revision: 3/)).toBeInTheDocument();
  const id = vi.mocked(api.apply).mock.calls[0][1].request_id;
  expect(vi.mocked(api.receipt).mock.calls.map(call => call[0])).toEqual([id, id]);
  fireEvent.click(newAction()); expect(screen.getByText(/Draft baseline revision: 3/)).toBeInTheDocument(); expect(api.apply).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('checkbox', { name: /Confirm this is an application-owned declaration/ })).not.toBeChecked();
});

it('a manual GET resolves an in-flight write; a later invalid reply cannot overwrite the fact or enable a second PUT', async () => {
  const pending = deferred<ApiResult<Receipt>>(); vi.mocked(api.apply).mockReturnValue(pending.promise);
  vi.mocked(api.receipt).mockImplementation(async request => result(receipt(vi.mocked(api.apply).mock.calls[0][1], { requestId: request })));
  mount(<OrchestrationPanel />); await selectTeam(); await prepare(); await apply(false);
  await waitFor(() => expect(api.apply).toHaveBeenCalledTimes(1)); fireEvent.doubleClick(screen.getByRole('button', { name: 'Commit the reviewed candidate' }));
  fireEvent.click(read()); await screen.findByText('Immutable original receipt'); expect(newAction()).toBeDisabled();
  await act(async () => pending.resolve(result(receipt(vi.mocked(api.apply).mock.calls[0][1], { version: 0 }))));
  await screen.findByText('Invalid original receipt / 原回执无法核验'); expect(screen.getByText('Original request state: committed')).toBeInTheDocument();
  expect(screen.getByText('Immutable original receipt')).toBeInTheDocument(); expect(newAction()).toBeEnabled(); expect(api.apply).toHaveBeenCalledTimes(1);
});
