import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, afterEach, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { ConfigProvider } from 'antd';
import { cmsQueueApi as api } from '@/api/cmsQueue';
import { ApiRequestError } from '@/api/client';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import CmsQueuePanel from './CmsQueuePanel';
import { deferred, item, itemId, receipt, requestId, result, source, state } from './testFixtures';
import type * as SessionAccessModule from '@/api/sessionAccess';
vi.mock('@/api/sessionAccess', async importOriginal => {
  const actual = await importOriginal<typeof SessionAccessModule>();
  const access: Record<string, boolean> = { 'alicloud:read': true, 'alicloud:write': true };
  const identity = { access, roles: ['owned-admin'], superadmin: false };
  const has = (permission: string) => identity.access[permission] === true;
  return { ...actual, useSessionAccess: () => ({ identity, has, isLoading: false,
    allows: (path: string) => (actual.PAGE_PERMISSIONS[path] ?? []).every(has) }) };
});
const original = useAuthStore.getState();
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  useAuthStore.setState({ tenant: { id: 'cms-tenant', slug: 'cms' } as Tenant, sessionGeneration: 1 });
  vi.spyOn(api, 'state').mockResolvedValue(result(state()));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); useAuthStore.setState(original); });
function mount() { return render(<MemoryRouter><ConfigProvider theme={{ token: { motion: false } }}><CmsQueuePanel /></ConfigProvider></MemoryRouter>); }
async function ready() { await screen.findByText('actual-owned-event'); }
async function fill() {
  await ready(); fireEvent.change(screen.getByRole('textbox', { name: 'CMS name' }), { target: { value: 'owned-name' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Event content' }), { target: { value: 'owned-private-content' } });
}
it('starts with a pure GET and requires an explicit payload submission and Mock seed consent', async () => {
  const enqueue = vi.spyOn(api, 'enqueue').mockImplementation(async body => result(receipt(body.request_id)));
  const send = vi.spyOn(api, 'send'); const recover = vi.spyOn(api, 'recover'); mount(); await fill();
  expect(enqueue).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); expect(recover).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Explicitly initialize the owned Mock demo fixture' }));
  fireEvent.click(screen.getByRole('button', { name: 'Enqueue explicitly' }));
  await waitFor(() => expect(enqueue).toHaveBeenCalledTimes(1));
  expect(enqueue.mock.calls[0][0]).toMatchObject({ configuration_version: 1, expected_generation: 1, initialize_mock_fixture: true,
    items: [{ kind: 'event', name: 'owned-name', content: 'owned-private-content' }] });
  await screen.findByText('Original CMS request receipt'); expect(send).not.toHaveBeenCalled();
});
it('retains original UUID and draft after lost response; 404 does not unlock or resend', async () => {
  const enqueue = vi.spyOn(api, 'enqueue').mockRejectedValue(new ApiRequestError('private withheld', 0, 'network_error', false));
  const read = vi.spyOn(api, 'receipt').mockRejectedValue(new ApiRequestError('missing', 404, 'not_found', false));
  mount(); await fill(); fireEvent.click(screen.getByRole('button', { name: 'Enqueue explicitly' }));
  await waitFor(() => expect(enqueue).toHaveBeenCalledTimes(1));
  const originalId = enqueue.mock.calls[0][0].request_id;
  await waitFor(() => expect(screen.getByRole('button', { name: 'Read original receipt' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Read original receipt' }));
  await waitFor(() => expect(read).toHaveBeenCalledWith(originalId));
  expect(screen.getByRole('button', { name: 'Enqueue explicitly' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Reviewed; allow a new explicit operation' })).toBeDisabled();
  expect(screen.getByRole('textbox', { name: 'Event content' })).toHaveValue('owned-private-content');
  read.mockResolvedValue(result(receipt(originalId)));
  fireEvent.click(screen.getByRole('button', { name: 'Read original receipt' })); await screen.findByText('Original CMS request receipt');
  expect(enqueue).toHaveBeenCalledTimes(1); expect(screen.getByRole('button', { name: 'Enqueue explicitly' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Reviewed; allow a new explicit operation' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Enqueue explicitly' })).toBeEnabled());
});
it('Live confirmation is bound to the actual current configuration revision', async () => {
  vi.mocked(api.state).mockResolvedValue(result(state({ source: { ...source, mocked: false, transportMode: 'live' } })));
  const send = vi.spyOn(api, 'send'); mount(); await fill();
  fireEvent.click(screen.getAllByRole('radio')[0]);
  expect(screen.getByRole('button', { name: 'New explicit delivery intent' })).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Confirm this Live CMS delivery' }));
  expect(screen.getByRole('button', { name: 'New explicit delivery intent' })).toBeEnabled();
  vi.mocked(api.state).mockResolvedValue(result(state({ source: { ...source, configurationVersion: 2, mocked: false, transportMode: 'live' } })));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh by reading' }));
  await waitFor(() => expect(screen.getByRole('checkbox', { name: 'Confirm this Live CMS delivery' })).not.toBeChecked());
  expect(screen.getByRole('textbox', { name: 'Event content' })).toHaveValue('owned-private-content');
  expect(send).not.toHaveBeenCalled(); expect(screen.getByRole('button', { name: 'New explicit delivery intent' })).toBeDisabled();
});
it('Accepted can be locally settled without creating a delivery intent', async () => {
  vi.mocked(api.state).mockResolvedValue(result(state({ items: [item({ canSend: false, canRecoverLocal: true, canArchive: false })] })));
  const send = vi.spyOn(api, 'send'); const recover = vi.spyOn(api, 'recover').mockResolvedValue(result(item({ canSend: false })));
  mount(); await ready(); fireEvent.click(screen.getAllByRole('radio')[0]);
  expect(screen.getByRole('button', { name: 'New explicit delivery intent' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Settle locally only' }));
  await waitFor(() => expect(recover).toHaveBeenCalledWith(itemId)); expect(send).not.toHaveBeenCalled();
});
it('archives only the selected body with an explicit new UUID and retains the original receipt', async () => {
  const archive = vi.spyOn(api, 'archive').mockImplementation(async body => result(receipt(body.request_id, 'archive')));
  const send = vi.spyOn(api, 'send'); const recover = vi.spyOn(api, 'recover');
  mount(); await ready(); fireEvent.click(screen.getAllByRole('radio')[0]);
  fireEvent.click(screen.getByRole('button', { name: 'Archive content' }));
  await waitFor(() => expect(archive).toHaveBeenCalledTimes(1));
  const original = archive.mock.calls[0][0];
  expect(original).toEqual({ request_id: expect.any(String), expected_generation: 1, item_ids: [itemId] });
  await screen.findByText('Original CMS request receipt');
  expect(screen.getByRole('textbox', { name: 'Original CMS request UUID' })).toHaveValue(original.request_id);
  expect(send).not.toHaveBeenCalled(); expect(recover).not.toHaveBeenCalled();
});
it('a late response cannot cross tenant A to B to A or restore the old receipt', async () => {
  const delayed = deferred<ReturnType<typeof result<ReturnType<typeof receipt>>>>();
  const read = vi.spyOn(api, 'receipt').mockReturnValue(delayed.promise);
  mount(); await ready();
  fireEvent.change(screen.getByRole('textbox', { name: 'Original CMS request UUID' }), { target: { value: requestId } });
  fireEvent.click(screen.getByRole('button', { name: 'Read original receipt' })); await waitFor(() => expect(read).toHaveBeenCalledTimes(1));
  await act(async () => { useAuthStore.setState({ tenant: { id: 'other', slug: 'other' } as Tenant, sessionGeneration: 2 }); });
  await act(async () => { useAuthStore.setState({ tenant: { id: 'cms-tenant', slug: 'cms' } as Tenant, sessionGeneration: 3 }); delayed.resolve(result(receipt())); });
  expect(screen.queryByText('Original CMS request receipt')).not.toBeInTheDocument();
});

it.each([403, 409, 412])('retains the original intent after post-claim HTTP %s and rejects another receipt purpose', async status => {
  const enqueue = vi.spyOn(api, 'enqueue').mockRejectedValue(new ApiRequestError('not confirmed', status, 'forbidden', false));
  const read = vi.spyOn(api, 'receipt'); mount(); await fill();
  fireEvent.click(screen.getByRole('button', { name: 'Enqueue explicitly' }));
  await waitFor(() => expect(enqueue).toHaveBeenCalledTimes(1));
  const originalId = enqueue.mock.calls[0][0].request_id;
  await waitFor(() => expect(screen.getByRole('button', { name: 'Read original receipt' })).toBeEnabled());
  const reset = screen.getByRole('button', { name: 'Reviewed; allow a new explicit operation' });
  expect(reset).toBeDisabled(); expect(screen.getByRole('button', { name: 'Enqueue explicitly' })).toBeDisabled();
  read.mockResolvedValue(result(receipt(originalId, 'archive')));
  fireEvent.click(screen.getByRole('button', { name: 'Read original receipt' }));
  await waitFor(() => expect(read).toHaveBeenCalledWith(originalId));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Read original receipt' })).toBeEnabled());
  expect(reset).toBeDisabled(); expect(screen.queryByText('Original CMS request receipt')).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Original CMS request UUID' })).toHaveValue(originalId);
  expect(screen.getByRole('textbox', { name: 'Event content' })).toHaveValue('owned-private-content');
  read.mockResolvedValue(result(receipt(originalId)));
  fireEvent.click(screen.getByRole('button', { name: 'Read original receipt' }));
  await screen.findByText('Original CMS request receipt'); expect(reset).toBeEnabled();
  expect(enqueue).toHaveBeenCalledTimes(1);
});
