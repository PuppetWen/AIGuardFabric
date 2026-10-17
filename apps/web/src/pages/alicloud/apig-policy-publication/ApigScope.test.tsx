import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { apigPublicationApi as api } from '@/api/apigPolicyPublication';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import type { ApiResult } from '@/api/dataSource';
import type { ApigOperation, ApigPublicationState } from '@/types/apigPolicyPublication';
import ApigPolicyPublicationPanel from './ApigPolicyPublicationPanel';
import { deferred, operation, operationId, policyId, result, state, target } from './testFixtures';
import { installHarness, mount } from './testHarness';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('uses native filtered pages and preserves an exact selected revision outside the loaded page', async () => {
  const first = state(), second = { ...first.sources.items[0], policyId: '10000000-0000-4000-8000-000000000099', name: 'Second page actual policy' };
  vi.mocked(api.state).mockImplementation(async query => result(state({ sources: { ...first.sources,
    items: query?.source_page === 2 ? [second] : first.sources.items, page: query?.source_page ?? 1,
    total: query?.source_eligible_only ? 1 : 21, policyCount: 21, eligibleCount: 1, totalPages: query?.source_eligible_only ? 1 : 2, truncated: query?.source_page !== 2 } })));
  mount(<ApigPolicyPublicationPanel />); fireEvent.click(await screen.findByRole('button', { name: 'Choose platform policy Actual projectable policy v4' }));
  fireEvent.click(screen.getByTitle('2')); await screen.findByRole('button', { name: 'Choose platform policy Second page actual policy v4' });
  expect(api.state).toHaveBeenLastCalledWith({ source_page: 2, source_page_size: 20, source_eligible_only: false }, expect.any(AbortSignal));
  expect(screen.getByText(`Retained selected source revision: ${policyId} @ v4`)).toBeInTheDocument();
  expect(screen.getByText(/The selected revision is not loaded on this page/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Show only server-eligible sources' }));
  await waitFor(() => expect(api.state).toHaveBeenLastCalledWith({ source_page: 1, source_page_size: 20, source_eligible_only: true }, expect.any(AbortSignal)));
  await screen.findByRole('button', { name: 'Choose platform policy Actual projectable policy v4' });
  expect(screen.getByText(`Retained selected source revision: ${policyId} @ v4`)).toBeInTheDocument();
});
it('shows unavailable-source reasons without choosing an arbitrary ID or fabricating a successful query', async () => {
  const candidate = vi.spyOn(api, 'preview');
  vi.mocked(api.state).mockResolvedValue(result(state({ sources: { ...state().sources, items: [{ ...state().sources.items[0], eligible: false, source: null,
    reason: 'This quota is a day window and cannot be projected' }], eligibleCount: 0 } })));
  mount(<ApigPolicyPublicationPanel />); await screen.findByText(/This quota is a day window/);
  expect(screen.getByRole('button', { name: 'Choose platform policy Actual projectable policy v4' })).toBeDisabled();
  expect(screen.getByText('Retained selected source revision: —')).toBeInTheDocument(); expect(candidate).not.toHaveBeenCalled();
  vi.mocked(api.state).mockRejectedValue(new Error('Signed source registry unavailable'));
  fireEvent.click(screen.getByRole('button', { name: /Refresh APIG local state to compare/ })); await screen.findByText('Signed source registry unavailable');
  expect(screen.getByText('Retained selected source revision: —')).toBeInTheDocument(); expect(candidate).not.toHaveBeenCalled();
});
it.each(['tenant', 'session', 'tenant-roundtrip'])('clears only owned recovery parameters and rejects a late receipt across a %s change', async change => {
  window.history.replaceState({ idx: 3, key: 'retain-key', usr: { retain: true } }, '', '/alicloud?tab=apig-policy&keep=user-view#guide');
  const pending = deferred<ApiResult<ApigOperation>>(), read = vi.spyOn(api, 'receipt').mockReturnValue(pending.promise);
  mount(<ApigPolicyPublicationPanel />); await screen.findByText(target.sourceLabel);
  fireEvent.change(screen.getByRole('textbox', { name: 'APIG publication original request UUID' }), { target: { value: operationId } });
  fireEvent.click(screen.getByRole('button', { name: /Read original APIG receipt \(GET only\)$/ })); await waitFor(() => expect(read).toHaveBeenCalledTimes(1));
  const signal = read.mock.calls[0][1];
  vi.mocked(api.state).mockResolvedValue(result(state({ binding: { ...target, sourceLabel: 'new-scope-source' } })));
  act(() => {
    if (change === 'session') useAuthStore.setState({ sessionGeneration: 2 });
    else { useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 });
      if (change === 'tenant-roundtrip') useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 3 }); }
  });
  await screen.findByText('new-scope-source'); await act(async () => { pending.resolve(result(operation())); });
  expect(signal?.aborted).toBe(true); expect(screen.queryByText('Original APIG request receipt')).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'APIG publication original request UUID' })).toHaveValue('');
  const params = new URLSearchParams(window.location.search); expect(params.has('apig_request_id')).toBe(false);
  expect(params.get('tab')).toBe('apig-policy'); expect(params.get('keep')).toBe('user-view'); expect(window.location.hash).toBe('#guide');
  expect(window.history.state).toMatchObject({ idx: 3, key: 'retain-key', usr: { retain: true } }); expect(read).toHaveBeenCalledTimes(1);
});
it('aborts a previous tenant state read and never renders its later source or policy options', async () => {
  const pending = deferred<ApiResult<ApigPublicationState>>(); vi.mocked(api.state).mockReturnValueOnce(pending.promise);
  mount(<ApigPolicyPublicationPanel />); await waitFor(() => expect(api.state).toHaveBeenCalledTimes(1));
  const signal = vi.mocked(api.state).mock.calls[0][1];
  vi.mocked(api.state).mockResolvedValue(result(state({ binding: { ...target, sourceLabel: 'Current tenant evidence' }, sources: { ...state().sources, items: [] } })));
  act(() => useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 }));
  await screen.findByText('Current tenant evidence'); await act(async () => { pending.resolve(result(state({ binding: { ...target, sourceLabel: 'Prior tenant private source' } }))); });
  expect(signal?.aborted).toBe(true); expect(screen.queryByText('Prior tenant private source')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Choose platform policy/ })).not.toBeInTheDocument();
});
it('preserves the same recovery input, UUID and focus when the first local state GET finishes', async () => {
  const pending = deferred<ApiResult<ApigPublicationState>>(); vi.mocked(api.state).mockReturnValueOnce(pending.promise);
  const read = vi.spyOn(api, 'receipt').mockResolvedValue(result(operation())); mount(<ApigPolicyPublicationPanel />);
  const input = screen.getByRole('textbox', { name: 'APIG publication original request UUID' });
  fireEvent.change(input, { target: { value: operationId } }); act(() => input.focus());
  expect(input).toHaveValue(operationId); expect(input).toHaveFocus(); expect(read).not.toHaveBeenCalled();
  await act(async () => { pending.resolve(result(state())); }); await screen.findByText(target.sourceLabel);
  expect(input.isConnected).toBe(true); expect(screen.getByRole('textbox', { name: 'APIG publication original request UUID' })).toBe(input);
  expect(input).toHaveValue(operationId); expect(input).toHaveFocus(); expect(read).not.toHaveBeenCalled();
  const button = screen.getByRole('button', { name: /Read original APIG receipt \(GET only\)$/ }); expect(button).toBeEnabled(); fireEvent.click(button);
  await screen.findByText('Original APIG request receipt'); expect(read).toHaveBeenCalledWith(operationId, expect.any(AbortSignal));
});
