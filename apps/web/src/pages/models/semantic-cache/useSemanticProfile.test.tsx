import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { semanticProfileApi, type SemanticProfile } from '@/api/semanticCacheProfile';
import { gatewayApi } from '@/api/gateway';
import type { ApiResult } from '@/api/dataSource';
import { ApiRequestError } from '@/api/transport';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import { useSemanticProfile } from './useSemanticProfile';
import { deferred, endpoint, profile, result } from './testFixtures';
import { toMicroCurrency, validInput } from './validation';

const original = useAuthStore.getState();
beforeEach(() => {
  useAuthStore.setState({ tenant: { id: 'one', slug: 'one' } as Tenant, sessionGeneration: 1 });
  vi.spyOn(semanticProfileApi, 'read').mockResolvedValue(result(profile()));
  vi.spyOn(gatewayApi, 'list').mockResolvedValue(result({ items: [endpoint()] }));
  vi.spyOn(semanticProfileApi, 'save').mockImplementation(async body => result(profile({ version: body.expected_version + 1,
    enabled: body.enabled, settings: body.settings })));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); useAuthStore.setState(original); });
async function mount(canRead = true, canWrite = true) {
  const view = renderHook(() => useSemanticProfile(canRead, canWrite));
  if (canRead) await waitFor(() => expect(view.result.current.busy).toBe(false));
  return view;
}

it('reads real configuration on mount and never writes or tests a provider automatically', async () => {
  const view = await mount();
  expect(view.result.current.baseline).toBe(7); expect(view.result.current.endpoints).toHaveLength(1);
  expect(semanticProfileApi.save).not.toHaveBeenCalled();
});
it('enforces read and write capabilities in handlers, even outside disabled buttons', async () => {
  const readOnly = await mount(true, false);
  act(() => { readOnly.result.current.setEnabled(false); readOnly.result.current.updateSettings({ ttl_seconds: 1 }); });
  await act(async () => { await readOnly.result.current.save(); });
  expect(readOnly.result.current.draft).toEqual({ enabled: true, settings: profile().settings });
  expect(semanticProfileApi.save).not.toHaveBeenCalled();
  readOnly.unmount(); vi.mocked(semanticProfileApi.read).mockClear();
  await mount(false, false); expect(semanticProfileApi.read).not.toHaveBeenCalled();
});
it('synchronously locks a PUT so double clicks cannot dispatch a second request', async () => {
  const slow = deferred<ApiResult<SemanticProfile>>();
  vi.mocked(semanticProfileApi.save).mockReturnValue(slow.promise);
  const view = await mount(); let first!: Promise<void>;
  act(() => { first = view.result.current.save(); void view.result.current.save(); });
  expect(semanticProfileApi.save).toHaveBeenCalledTimes(1);
  await act(async () => { slow.resolve(result(profile({ version: 8 }))); await first; });
  expect(view.result.current.baseline).toBe(8); expect(view.result.current.blocked).toBeUndefined();
});
it('retains a conflicting draft and old CAS version through GET until explicit adoption', async () => {
  vi.mocked(semanticProfileApi.save).mockRejectedValue(new ApiRequestError('Conflict', 409, 'conflict', false));
  const view = await mount();
  act(() => view.result.current.updateSettings({ ttl_seconds: 123 }));
  await act(async () => { await view.result.current.save(); });
  expect(view.result.current.blocked).toBe('conflict'); expect(view.result.current.draft.settings?.ttl_seconds).toBe(123);
  act(() => view.result.current.adoptCurrent()); expect(view.result.current.blocked).toBe('conflict');
  vi.mocked(semanticProfileApi.read).mockResolvedValue(result(profile({ version: 9 })));
  await act(async () => { await view.result.current.read(); await view.result.current.save(); });
  expect(view.result.current.baseline).toBe(7); expect(view.result.current.current?.version).toBe(9);
  expect(view.result.current.draft.settings?.ttl_seconds).toBe(123); expect(semanticProfileApi.save).toHaveBeenCalledTimes(1);
  act(() => view.result.current.adoptCurrent()); expect(view.result.current.baseline).toBe(9);
  expect(view.result.current.draft.settings?.ttl_seconds).toBe(300);
});
it('does not treat a matching current configuration as an original receipt after a lost reply', async () => {
  vi.mocked(semanticProfileApi.save).mockRejectedValue(new ApiRequestError('Lost reply', 0, 'network'));
  const view = await mount();
  await act(async () => { await view.result.current.save(); });
  const submitted = view.result.current.submitted;
  vi.mocked(semanticProfileApi.read).mockResolvedValue(result(profile({ version: 8 })));
  await act(async () => { await view.result.current.read(); await view.result.current.save(); });
  expect(view.result.current.blocked).toBe('unknown'); expect(view.result.current.baseline).toBe(7);
  expect(view.result.current.submitted).toEqual(submitted); expect(semanticProfileApi.save).toHaveBeenCalledTimes(1);
});
it('a failed recovery read cannot authorize adoption or another PUT', async () => {
  vi.mocked(semanticProfileApi.save).mockRejectedValue(new ApiRequestError('Timeout', 408, 'timeout'));
  const view = await mount(); await act(async () => { await view.result.current.save(); });
  vi.mocked(semanticProfileApi.read).mockRejectedValue(new ApiRequestError('Unavailable', 503, 'unavailable'));
  await act(async () => { await view.result.current.read(); });
  act(() => view.result.current.adoptCurrent());
  await act(async () => { await view.result.current.save(); });
  expect(view.result.current.readAfterSave).toBe(false); expect(view.result.current.blocked).toBe('unknown');
  expect(semanticProfileApi.save).toHaveBeenCalledTimes(1);
});
it('permits manual correction after a confirmed 412 without silently adopting a newer version', async () => {
  vi.mocked(semanticProfileApi.save).mockRejectedValueOnce(new ApiRequestError('Endpoint stale', 412, 'stale', false));
  const view = await mount(); await act(async () => { await view.result.current.save(); });
  expect(view.result.current.blocked).toBeUndefined();
  act(() => view.result.current.updateSettings({ chat_model_revision: 'chat-r2' }));
  await act(async () => { await view.result.current.save(); });
  expect(semanticProfileApi.save).toHaveBeenNthCalledWith(2, expect.objectContaining({ expected_version: 7,
    settings: expect.objectContaining({ chat_model_revision: 'chat-r2' }) }));
});
it('rejects an imprecise server version before a write can be attempted', async () => {
  vi.mocked(semanticProfileApi.read).mockResolvedValue(result(profile({ version: Number.MAX_SAFE_INTEGER + 1 })));
  const view = await mount(); await act(async () => { await view.result.current.save(); });
  expect(view.result.current.baseline).toBeUndefined(); expect(semanticProfileApi.save).not.toHaveBeenCalled();
});
it('keeps a malformed successful version response unknown instead of advancing CAS', async () => {
  vi.mocked(semanticProfileApi.save).mockResolvedValue(result(profile({ version: 100 })));
  const view = await mount(); await act(async () => { await view.result.current.save(); });
  expect(view.result.current.baseline).toBe(7); expect(view.result.current.blocked).toBe('unknown');
});
it('ignores a late save after tenant A to B to A with changed session generations', async () => {
  const slow = deferred<ApiResult<SemanticProfile>>(); vi.mocked(semanticProfileApi.save).mockReturnValue(slow.promise);
  const view = await mount(); let write!: Promise<void>;
  act(() => { write = view.result.current.save(); });
  act(() => useAuthStore.setState({ tenant: { id: 'two', slug: 'two' } as Tenant, sessionGeneration: 2 }));
  act(() => useAuthStore.setState({ tenant: { id: 'one', slug: 'one' } as Tenant, sessionGeneration: 3 }));
  await act(async () => { slow.resolve(result(profile({ version: 8 }))); await write; });
  expect(view.result.current.baseline).toBe(7); expect(view.result.current.current?.version).toBe(7);
});
it('converts provider prices exactly at microcurrency precision and rejects impossible reservation settings', () => {
  expect(toMicroCurrency(0.001234)).toBe(1234); expect(toMicroCurrency(0.0000001)).toBeUndefined();
  expect(toMicroCurrency(Number.MAX_VALUE)).toBeUndefined();
  expect(validInput({ expected_version: 0, enabled: false, settings: null })).toBe(true);
  expect(validInput({ expected_version: 0, enabled: true, settings: null })).toBe(false);
  const settings = profile().settings!;
  expect(validInput({ expected_version: 7, enabled: true, settings: { ...settings, mode: 'live', embedding_micro_per_1k: 0 } })).toBe(false);
  expect(validInput({ expected_version: 7, enabled: true, settings: { ...settings, dimensions: 4097 } })).toBe(false);
  expect(validInput({ expected_version: 7, enabled: true, settings: { ...settings, chat_model_revision: 'invalid@revision' } })).toBe(false);
});
