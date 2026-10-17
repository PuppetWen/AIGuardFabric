import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { message } from 'antd';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { api, ApiRequestError } from '@/api/client';
import { policiesApi } from '@/api/policies';
import { policy as adaptPolicy } from '@/api/adapters/governance';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import type { Policy, Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import PoliciesPage from '../PoliciesPage';
import { policyDeferred, policyFixture, policyResult } from './policyTestFixtures';

vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
const originalAuth = useAuthStore.getState(), caches: QueryClient[] = [];
const localCode = 'input.tool_name == "local draft" ? {"action":"deny"} : {}';
let rights: Set<string>;
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 1 });
  rights = new Set(['policies:read', 'policies:write', 'policies:delete']);
  vi.mocked(useSessionAccess).mockImplementation(() => ({ has: (permission: string) => rights.has(permission), isLoading: false }) as ReturnType<typeof useSessionAccess>);
  vi.spyOn(api, 'policies').mockResolvedValue(policyResult({ items: [policyFixture()], total: 1, page: 1, pageSize: 50 }));
  vi.spyOn(policiesApi, 'get').mockResolvedValue(policyResult(policyFixture(3, { description: 'New reviewed description', code: 'true ? {"action":"deny"} : {}' })));
});
afterEach(async () => {
  cleanup(); caches.forEach(cache => cache.clear()); caches.length = 0;
  act(() => message.destroy()); vi.restoreAllMocks(); useAuthStore.setState(originalAuth);
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});
async function mount() {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } }); caches.push(cache);
  render(<QueryClientProvider client={cache}><MemoryRouter><PoliciesPage /></MemoryRouter></QueryClientProvider>);
  fireEvent.click(await screen.findByText('Owned policy')); await screen.findByText('Save uses revision v1');
}
function edit() {
  fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Unsaved local description' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Rego / CEL code' }), { target: { value: localCode } });
  fireEvent.change(screen.getByLabelText('Priority (lower matches first)'), { target: { value: '85' } });
}
function expectDraft() {
  expect(screen.getByLabelText('Description')).toHaveValue('Unsaved local description');
  expect(screen.getByRole('textbox', { name: 'Rego / CEL code' })).toHaveValue(localCode);
  expect(screen.getByLabelText('Priority (lower matches first)')).toHaveValue('85');
}
async function save() {
  const button = await screen.findByRole('button', { name: 'Save' });
  await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button);
}

it('keeps the whole draft and original save revision after 409 and an independent comparison read', async () => {
  const publish = vi.spyOn(policiesApi, 'save').mockRejectedValue(new ApiRequestError('Concurrent policy edit', 409, 'conflict', false));
  await mount(); edit(); await save(); await screen.findByText('Concurrent policy edit'); expectDraft();
  fireEvent.click(screen.getByRole('button', { name: 'Load latest revision to compare' }));
  await screen.findByText('Server revision v3'); expectDraft(); expect(screen.getByText('Save uses revision v1')).toBeInTheDocument();
  expect((screen.getByLabelText('Current policy draft') as HTMLTextAreaElement).value).toContain('Unsaved local description');
  expect(publish).toHaveBeenCalledTimes(1); await save(); await screen.findByText('Concurrent policy edit');
  expect(publish).toHaveBeenLastCalledWith(expect.objectContaining({ id: policyFixture().id, code: localCode,
    description: 'Unsaved local description', priority: 85 }), 1);
});
it('requires explicit adoption without publication and only a later manual save uses the adopted revision', async () => {
  const publish = vi.spyOn(policiesApi, 'save').mockResolvedValue(policyResult(policyFixture(4)));
  await mount(); edit(); fireEvent.click(screen.getByRole('button', { name: 'Load latest revision to compare' }));
  await screen.findByText('Server revision v3'); fireEvent.click(screen.getByRole('button', { name: 'Adopt latest policy explicitly' }));
  await screen.findByText('Replace the draft and save revision?'); expectDraft(); expect(publish).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Confirm adopting latest policy' }));
  await screen.findByText('Save uses revision v3');
  expect(screen.getByLabelText('Description')).toHaveValue('New reviewed description');
  expect(screen.getByRole('textbox', { name: 'Rego / CEL code' })).toHaveValue('true ? {"action":"deny"} : {}');
  expect(publish).not.toHaveBeenCalled(); await save();
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument());
  expect(publish).toHaveBeenCalledWith(expect.objectContaining({ description: 'New reviewed description' }), 3);
});
it('compares the source actually saved from form conditions and never substitutes old code for an incomplete draft', async () => {
  const publish = vi.spyOn(policiesApi, 'save').mockRejectedValue(new ApiRequestError('Concurrent policy edit', 409, 'conflict', false));
  const source = '(input.domain == "example.org") ? {"action":"deny"} : {}';
  await mount(); fireEvent.click(screen.getByRole('radio', { name: 'Form mode' }));
  fireEvent.change(screen.getByPlaceholderText('Value'), { target: { value: 'example.org' } });
  fireEvent.click(screen.getByRole('button', { name: 'Load latest revision to compare' })); await screen.findByText('Server revision v3');
  const compared = JSON.parse((screen.getByLabelText('Current policy draft') as HTMLTextAreaElement).value);
  expect(compared).toMatchObject({ version: 1, code: source, expression: 'request.host == example.org' });
  expect(screen.getByText('Save uses revision v1')).toBeInTheDocument(); expect(publish).not.toHaveBeenCalled();
  await save(); await screen.findByText('Concurrent policy edit');
  expect(publish).toHaveBeenCalledWith(expect.objectContaining({ code: source }), 1);
  fireEvent.change(screen.getByPlaceholderText('Value'), { target: { value: '' } });
  await screen.findByText(/Conditions are incomplete; the source to save cannot be generated\./);
  expect(JSON.parse((screen.getByLabelText('Current policy draft') as HTMLTextAreaElement).value).code).toBeNull();
  expect(screen.getByText('Save uses revision v1')).toBeInTheDocument(); expect(publish).toHaveBeenCalledOnce();
});
it('preserves 400/404 drafts and deletes only after explicit confirmation with the reviewed revision', async () => {
  vi.spyOn(policiesApi, 'save').mockRejectedValue(new ApiRequestError('Invalid condition', 400, 'validation', false));
  vi.mocked(policiesApi.get).mockRejectedValue(new ApiRequestError('Policy unavailable', 404, 'not-found', false));
  const remove = vi.spyOn(policiesApi, 'delete').mockRejectedValue(new ApiRequestError('Delete conflict', 409, 'conflict', false));
  await mount(); edit(); await save(); await screen.findByText('Invalid condition'); expectDraft();
  fireEvent.click(screen.getByRole('button', { name: 'Load latest revision to compare' })); await screen.findByText('Policy unavailable'); expectDraft();
  fireEvent.click(screen.getByRole('button', { name: 'Delete current policy' })); await screen.findByText('Delete policy Owned policy?');
  expect(remove).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: 'Confirm policy deletion' }));
  await screen.findByText('Delete conflict'); expectDraft(); expect(remove).toHaveBeenCalledWith(policyFixture().id, 1);
});
it('locks writes while validation/save is pending and does not duplicate a business request', async () => {
  const pending = policyDeferred<ReturnType<typeof policyResult<ReturnType<typeof policyFixture>>>>();
  const publish = vi.spyOn(policiesApi, 'save').mockReturnValue(pending.promise);
  await mount(); edit(); await save(); await waitFor(() => expect(publish).toHaveBeenCalledTimes(1));
  expect(screen.getByLabelText('Description')).toBeDisabled(); expect(screen.getByRole('button', { name: 'Delete current policy' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Save' })); expect(publish).toHaveBeenCalledTimes(1);
  await act(async () => { pending.resolve(policyResult(policyFixture(2))); });
});
it.each(['tenant', 'session'])('clears old draft on %s changes and discards a late private comparison response', async change => {
  const pending = policyDeferred<ReturnType<typeof policyResult<ReturnType<typeof policyFixture>>>>();
  vi.mocked(policiesApi.get).mockReturnValue(pending.promise);
  await mount(); edit(); fireEvent.click(screen.getByRole('button', { name: 'Load latest revision to compare' }));
  await waitFor(() => expect(policiesApi.get).toHaveBeenCalledOnce());
  act(() => useAuthStore.setState({ sessionGeneration: 2, ...(change === 'tenant' ? { tenant: { id: 'tenant-two', slug: 'two' } as Tenant } : {}) }));
  await waitFor(() => expect(screen.queryByLabelText('Description')).not.toBeInTheDocument());
  await act(async () => { pending.resolve(policyResult(policyFixture(99, { description: 'Late private content' }))); });
  expect(screen.queryByText('Server revision v99')).not.toBeInTheDocument(); expect(screen.queryByText('Late private content')).not.toBeInTheDocument();
});
it('does not close a new-session drawer or report a late old save as its success', async () => {
  const pending = policyDeferred<ReturnType<typeof policyResult<ReturnType<typeof policyFixture>>>>();
  const publish = vi.spyOn(policiesApi, 'save').mockReturnValue(pending.promise);
  await mount(); edit(); await save(); await waitFor(() => expect(publish).toHaveBeenCalledOnce());
  act(() => useAuthStore.setState({ sessionGeneration: 2 }));
  await waitFor(() => expect(screen.queryByLabelText('Description')).not.toBeInTheDocument());
  fireEvent.click(await screen.findByText('Owned policy')); await screen.findByText('Save uses revision v1'); edit();
  await act(async () => { pending.resolve(policyResult(policyFixture(2))); });
  expectDraft(); expect(screen.getByText('Save uses revision v1')).toBeInTheDocument();
});
it('does not dispatch a validated old draft if the tenant changes during local validation', async () => {
  const publish = vi.spyOn(policiesApi, 'save').mockResolvedValue(policyResult(policyFixture(2)));
  await mount(); edit(); fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  act(() => useAuthStore.setState({ tenant: { id: 'tenant-two', slug: 'two' } as Tenant, sessionGeneration: 2 }));
  await act(async () => { await Promise.resolve(); });
  await waitFor(() => expect(screen.queryByLabelText('Description')).not.toBeInTheDocument()); expect(publish).not.toHaveBeenCalled();
});
it('locks deletion and ignores its late completion after reauthentication', async () => {
  const pending = policyDeferred<ReturnType<typeof policyResult<{ deleted: string }>>>();
  const remove = vi.spyOn(policiesApi, 'delete').mockReturnValue(pending.promise);
  await mount(); fireEvent.click(screen.getByRole('button', { name: 'Delete current policy' }));
  await screen.findByText('Delete policy Owned policy?'); fireEvent.click(screen.getByRole('button', { name: 'Confirm policy deletion' }));
  await waitFor(() => expect(remove).toHaveBeenCalledOnce()); expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
  act(() => useAuthStore.setState({ sessionGeneration: 2 }));
  await waitFor(() => expect(screen.queryByLabelText('Description')).not.toBeInTheDocument());
  fireEvent.click(await screen.findByText('Owned policy')); await screen.findByText('Save uses revision v1'); edit();
  await act(async () => { pending.resolve(policyResult({ deleted: policyFixture().id })); }); expectDraft();
});
it('keeps a duplicate-name creation draft and never silently updates an existing policy', async () => {
  const publish = vi.spyOn(policiesApi, 'save').mockRejectedValue(new ApiRequestError('Duplicate policy name', 409, 'conflict', false));
  await mount(); fireEvent.click(screen.getByRole('button', { name: 'Close' }));
  fireEvent.click(await screen.findByRole('button', { name: /Policy editor$/ }));
  fireEvent.change(screen.getByLabelText('Policy name'), { target: { value: 'Owned policy' } });
  fireEvent.click(screen.getByRole('radio', { name: 'Rego / CEL code' })); await save(); await screen.findByText('Duplicate policy name');
  expect(screen.getByLabelText('Policy name')).toHaveValue('Owned policy');
  expect(publish).toHaveBeenCalledWith(expect.objectContaining({ name: 'Owned policy' }), undefined);
  expect(publish.mock.calls[0][0].id).toBeUndefined();
  expect(screen.queryByRole('button', { name: 'Load latest revision to compare' })).not.toBeInTheDocument();
});
it.each([false, true])('keeps reader inspection and separates delete=%s permission from policy publication', async canDelete => {
  rights = new Set(['policies:read', ...(canDelete ? ['policies:delete'] : [])]); await mount();
  expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
  if (canDelete) expect(screen.getByRole('button', { name: 'Delete current policy' })).toBeEnabled();
  else expect(screen.queryByRole('button', { name: 'Delete current policy' })).not.toBeInTheDocument();
  expect(screen.getByLabelText('Description')).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Load latest revision to compare' })); await screen.findByText('Server revision v3');
  if (canDelete) expect(screen.getByRole('button', { name: 'Adopt latest policy explicitly' })).toBeEnabled();
  else expect(screen.getByRole('button', { name: 'Adopt latest policy explicitly' })).toBeDisabled();
});
it.each([['quota', 'quota'], ['circuitbreak', 'circuit-break'], ['approval', 'approval']])(
  'retains real server %s when a user changes only description', async (rawAction, action) => {
    const original = adaptPolicy({ ...policyFixture(), action: rawAction }) as unknown as Policy;
    vi.mocked(api.policies).mockResolvedValue(policyResult({ items: [original], total: 1, page: 1, pageSize: 50 }));
    const publish = vi.spyOn(policiesApi, 'save').mockRejectedValue(new ApiRequestError('Draft retained', 400, 'validation', false));
    await mount(); fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Metadata edit' } }); await save();
    await screen.findByText('Draft retained'); expect(publish).toHaveBeenCalledWith(expect.objectContaining({
      action, code: original.code, description: 'Metadata edit', rawAction,
    }), 1);
  },
);
it('shows unknown server actions without allowing publication or adoption of an unsupported latest policy', async () => {
  const unknown = adaptPolicy({ ...policyFixture(), action: 'future-action' }) as unknown as Policy;
  vi.mocked(api.policies).mockResolvedValue(policyResult({ items: [unknown], total: 1, page: 1, pageSize: 50 }));
  vi.mocked(policiesApi.get).mockResolvedValue(policyResult({ ...unknown, version: 3 }));
  const publish = vi.spyOn(policiesApi, 'save'); await mount();
  expect(screen.getByText(/Server action future-action cannot be edited/)).toBeInTheDocument();
  const button = screen.getByRole('button', { name: 'Save' }); expect(button).toBeDisabled(); fireEvent.click(button);
  fireEvent.click(screen.getByRole('button', { name: 'Load latest revision to compare' })); await screen.findByText('Server revision v3');
  expect(screen.getByText(/Latest policy action future-action is unknown/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Adopt latest policy explicitly' })).toBeDisabled();
  expect(screen.getByText('Save uses revision v1')).toBeInTheDocument(); expect(publish).not.toHaveBeenCalled();
});
