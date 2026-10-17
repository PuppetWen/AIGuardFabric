import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import { callApi, downloadArtifact } from './transport';

const tenant = { id: 'scope-tenant-one', slug: 'scope-one' } as Tenant;
const other = { id: 'scope-tenant-two', slug: 'scope-two' } as Tenant;
const jwt = (seconds: number) => `header.${btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + seconds }))}.signature`;
const pair = () => ({ access_token: jwt(3600), refresh_token: 'scope-new-refresh' });
const fallback = (): never => { throw new Error('Scope changes must never use demo data'); };
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

beforeEach(() => {
  localStorage.clear(); useAuthStore.getState().reset();
  useAuthStore.getState().setSession({ tenant, token: jwt(-60), refreshToken: 'scope-refresh',
    displayName: 'Scope admin', role: 'owner', mustChangePassword: false });
});
afterEach(() => { vi.unstubAllGlobals(); useAuthStore.getState().reset(); localStorage.clear(); });

it.each(['POST', 'PUT', 'PATCH', 'DELETE'] as const)('never dispatches a %s mutation in another tenant when token refresh was pending', async method => {
  const refresh = deferred<Response>();
  const request = vi.fn(async (url: string) => url.endsWith('/auth/refresh') ? refresh.promise : Response.json({ saved: true }));
  vi.stubGlobal('fetch', request);
  const pending = callApi('/api/v1/quotas', fallback, { method, body: { name: 'old-tenant-rule', expected_version: 1 }, noFallback: true });
  const rejected = expect(pending).rejects.toMatchObject({ status: 409, code: 'session_changed', fallbackable: false });
  await vi.waitFor(() => expect(request).toHaveBeenCalledTimes(1));
  useAuthStore.getState().setTenant(other);
  refresh.resolve(Response.json(pair()));
  await rejected;
  expect(request.mock.calls.every(([url]) => url.endsWith('/auth/refresh'))).toBe(true);
  expect(useAuthStore.getState().tenant?.id).toBe(other.id);
});

it('allows normal refresh in the same tenant and snapshots both request body and query before it waits', async () => {
  const refresh = deferred<Response>();
  const rotated = pair();
  const request = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith('/auth/refresh')) return refresh.promise;
    expect((init?.headers as Record<string, string>)['X-AGF-Tenant']).toBe(tenant.id);
    expect((init?.headers as Record<string, string>).Authorization).toBe(`Bearer ${rotated.access_token}`);
    expect(JSON.parse(String(init?.body))).toEqual({ name: 'original', limit: 10 });
    expect(new URL(url, 'http://localhost').searchParams.get('q')).toBe('original');
    return Response.json({ saved: true });
  });
  vi.stubGlobal('fetch', request);
  const body = { name: 'original', limit: 10 };
  const query = { q: 'original' };
  const pending = callApi<{ saved: boolean }>('/api/v1/quotas', fallback, { method: 'POST', body, query, noFallback: true });
  await vi.waitFor(() => expect(request).toHaveBeenCalledTimes(1));
  body.name = 'edited while waiting'; body.limit = 100; query.q = 'edited';
  refresh.resolve(Response.json(rotated));
  expect((await pending).data.saved).toBe(true);
  expect(request).toHaveBeenCalledTimes(2);
});

it('never submits an old draft after a different login replaces the session in the same tenant', async () => {
  const refresh = deferred<Response>();
  const request = vi.fn(async (url: string) => url.endsWith('/auth/refresh') ? refresh.promise : Response.json({ saved: true }));
  vi.stubGlobal('fetch', request);
  const pending = callApi('/api/v1/quotas', fallback, { method: 'POST', body: { name: 'previous-login-draft' }, noFallback: true });
  const rejected = expect(pending).rejects.toMatchObject({ code: 'session_changed' });
  await vi.waitFor(() => expect(request).toHaveBeenCalledTimes(1));
  useAuthStore.getState().setSession({ tenant, token: 'new-session', displayName: 'New user', role: 'owner', mustChangePassword: false });
  refresh.resolve(Response.json(pair()));
  await rejected;
  expect(request).toHaveBeenCalledTimes(1);
  expect(useAuthStore.getState().token).toBe('new-session');
});

it('cancels an old mutation even when the user switches away and back before refresh completes', async () => {
  const refresh = deferred<Response>();
  const request = vi.fn(async (url: string) => url.endsWith('/auth/refresh') ? refresh.promise : Response.json({ saved: true }));
  vi.stubGlobal('fetch', request);
  const pending = callApi('/api/v1/quotas', fallback, { method: 'POST', body: { name: 'discarded-draft' }, noFallback: true });
  const rejected = expect(pending).rejects.toMatchObject({ code: 'session_changed' });
  await vi.waitFor(() => expect(request).toHaveBeenCalledTimes(1));
  useAuthStore.getState().setTenant(other);
  useAuthStore.getState().setTenant(tenant);
  refresh.resolve(Response.json(pair()));
  await rejected;
  expect(request).toHaveBeenCalledTimes(1);
  expect(useAuthStore.getState().tenant?.id).toBe(tenant.id);
});

it('does not cancel a pending mutation when the same tenant identity is selected again', async () => {
  const refresh = deferred<Response>();
  const request = vi.fn(async (url: string) => url.endsWith('/auth/refresh') ? refresh.promise : Response.json({ saved: true }));
  vi.stubGlobal('fetch', request);
  const pending = callApi<{ saved: boolean }>('/api/v1/quotas', fallback, { method: 'POST', body: { name: 'valid-draft' }, noFallback: true });
  await vi.waitFor(() => expect(request).toHaveBeenCalledTimes(1));
  useAuthStore.getState().setTenant({ ...tenant });
  refresh.resolve(Response.json(pair()));
  expect((await pending).data.saved).toBe(true);
  expect(request).toHaveBeenCalledTimes(2);
});

it('does not dispatch an old GET into the newly selected tenant after refresh', async () => {
  const refresh = deferred<Response>();
  const request = vi.fn(async (url: string) => url.endsWith('/auth/refresh') ? refresh.promise : Response.json({ items: [] }));
  vi.stubGlobal('fetch', request);
  const pending = callApi('/api/v1/assets', fallback, { noFallback: true });
  const rejected = expect(pending).rejects.toMatchObject({ code: 'session_changed' });
  await vi.waitFor(() => expect(request).toHaveBeenCalledTimes(1));
  useAuthStore.getState().setTenant(other);
  refresh.resolve(Response.json(pair()));
  await rejected;
  expect(request).toHaveBeenCalledTimes(1);
});

it('discards a successful old response when the tenant changes while its body is being read', async () => {
  const current = useAuthStore.getState();
  current.rotateTokens(current.sessionKey!, jwt(3600), 'healthy-refresh');
  let body!: ReadableStreamDefaultController<Uint8Array>;
  const stream = new ReadableStream<Uint8Array>({ start(controller) { body = controller; } });
  const response = new Response(stream, { headers: { 'Content-Type': 'application/json' } });
  const request = vi.fn(async () => response);
  vi.stubGlobal('fetch', request);
  const pending = callApi('/api/v1/assets', fallback, { noFallback: true });
  const rejected = expect(pending).rejects.toMatchObject({ code: 'session_changed' });
  await vi.waitFor(() => expect(response.bodyUsed).toBe(true));
  useAuthStore.getState().setTenant(other);
  body.enqueue(new TextEncoder().encode(JSON.stringify({ private_data: 'old tenant data' }))); body.close();
  await rejected;
  expect(request).toHaveBeenCalledTimes(1);
});

it('does not download the newly selected tenant artifact when a previous download waits for refresh', async () => {
  const refresh = deferred<Response>();
  const request = vi.fn(async (url: string) => url.endsWith('/auth/refresh') ? refresh.promise : new Response('private report'));
  vi.stubGlobal('fetch', request);
  const pending = downloadArtifact('/api/v1/reports/private/export', 'old-tenant-report.pdf');
  const rejected = expect(pending).rejects.toMatchObject({ code: 'session_changed' });
  await vi.waitFor(() => expect(request).toHaveBeenCalledTimes(1));
  useAuthStore.getState().setTenant(other);
  refresh.resolve(Response.json(pair()));
  await rejected;
  expect(request).toHaveBeenCalledTimes(1);
});

it('keeps public authentication callbacks valid when a login establishes a new session', async () => {
  const response = deferred<Response>();
  const request = vi.fn(async (_url: string, _init?: RequestInit) => response.promise);
  vi.stubGlobal('fetch', request);
  const pending = callApi<{ authenticated: boolean }>('/api/v1/auth/login', fallback, {
    method: 'POST', body: { username: 'scope-user', password: 'local-test-only', tenant: other.slug }, noFallback: true,
  });
  await vi.waitFor(() => expect(request).toHaveBeenCalledTimes(1));
  useAuthStore.getState().setSession({ tenant: other, token: jwt(3600), displayName: 'New login', role: 'owner', mustChangePassword: false });
  response.resolve(Response.json({ authenticated: true }));
  expect((await pending).data.authenticated).toBe(true);
  expect((request.mock.calls[0][1]?.headers as Record<string, string> | undefined)?.['X-AGF-Tenant']).toBeUndefined();
});
