import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import { markLive } from './dataSource';
import { useApiQuery } from './reactQuery';

const tenant = { id: 'cache-scope-one', slug: 'cache-one' } as Tenant;
const other = { id: 'cache-scope-two', slug: 'cache-two' } as Tenant;
const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
afterEach(() => { cleanup(); client.clear(); useAuthStore.getState().reset(); vi.restoreAllMocks(); });

it('rejects delayed data and retries for an inactive old tenant query instead of filling its cache with another tenant', async () => {
  useAuthStore.getState().setSession({ tenant, token: 'cache-test', displayName: 'Cache test', role: 'owner', mustChangePassword: false });
  const generation = useAuthStore.getState().sessionGeneration;
  const oldKey = ['agf', 'scope-cache', tenant.id, generation];
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  const calls: string[] = [];
  const read = vi.fn(async () => {
    const selected = useAuthStore.getState().tenant!.id;
    calls.push(selected);
    if (selected === tenant.id) await pending;
    return { data: { tenant: selected }, meta: { source: 'live' as const, elapsedMs: 0, at: Date.now() } };
  });
  function Probe() {
    const response = useApiQuery('scope-cache', read);
    return <span>{response.data?.data.tenant ?? 'loading'}</span>;
  }
  markLive();
  await act(async () => { render(<QueryClientProvider client={client}><Probe /></QueryClientProvider>); });
  await waitFor(() => expect(calls).toEqual([tenant.id]));
  await act(async () => { useAuthStore.getState().setTenant(other); });
  await screen.findByText(other.id);
  await act(async () => { release(); await pending; });
  await waitFor(() => expect(client.getQueryState(oldKey)?.status).toBe('error'));
  expect(client.getQueryData(oldKey)).toBeUndefined();
  const old = client.getQueryCache().find({ queryKey: oldKey, exact: true })!;
  await expect(old.fetch()).rejects.toMatchObject({ code: 'session_changed' });
  expect(calls).toEqual([tenant.id, other.id]);
  expect(screen.getByText(other.id)).toBeInTheDocument();
});
