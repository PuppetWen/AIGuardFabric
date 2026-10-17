import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import { writeAuthState } from '@/stores/authStorage';
import type { Tenant } from '@/types/domain';
import { logoutSession, sessionToken } from './session';
import { callApi } from './transport';
import { adaptLoginResponse } from './contract';

const tenant = { id: 'original-tenant', slug: 'original' } as Tenant;
const jwt = (seconds: number) => `header.${btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + seconds }))}.signature`;
const unavailable = (): never => { throw new Error('must not use demo fallback'); };
const pair = () => ({ access_token: jwt(3600), refresh_token: 'rotated-refresh' });

beforeEach(() => {
  localStorage.clear();
  useAuthStore.getState().reset();
  useAuthStore.getState().setSession({ token: jwt(-60), refreshToken: 'initial-refresh', tenant,
    displayName: 'Test', role: 'owner', mustChangePassword: false });
});
afterEach(() => { vi.unstubAllGlobals(); useAuthStore.getState().reset(); });

describe('console session rotation', () => {
  it('coalesces concurrent refreshes and uses the login tenant while retaining the selected tenant', async () => {
    const refreshed = pair();
    useAuthStore.getState().setTenant({ ...tenant, id: 'selected-tenant' });
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      const headers = init?.headers as Record<string,string>;
      if (url.endsWith('/auth/refresh')) {
        expect(headers['X-AGF-Tenant']).toBe('original-tenant');
        expect(JSON.parse(init?.body as string)).toEqual({ refresh_token: 'initial-refresh' });
        await Promise.resolve();
        return Response.json(refreshed);
      }
      expect(headers.Authorization).toBe(`Bearer ${refreshed.access_token}`);
      expect(headers['X-AGF-Tenant']).toBe('selected-tenant');
      return Response.json({ items: [] });
    });
    vi.stubGlobal('fetch',fetchMock);
    await Promise.all([1,2,3].map(()=>callApi('/api/v1/assets',unavailable,{noFallback:true})));
    expect(fetchMock.mock.calls.filter(([url])=>url.endsWith('/auth/refresh'))).toHaveLength(1);
    expect(useAuthStore.getState().refreshToken).toBe('rotated-refresh');
    expect(useAuthStore.getState().tenant?.id).toBe('selected-tenant');
  });

  it('does not restore a session after logout while a refresh request is pending', async () => {
    let resolveResponse!: (response: Response) => void;
    vi.stubGlobal('fetch',vi.fn(()=>new Promise<Response>(resolve=>{ resolveResponse=resolve; })));
    const pending = sessionToken();
    await vi.waitFor(()=>expect(resolveResponse).toBeTypeOf('function'));
    useAuthStore.getState().reset();
    resolveResponse(Response.json(pair()));
    expect(await pending).toBeNull();
    expect(useAuthStore.getState().token).toBeNull();
  });

  it('adopts a rotation already completed by another tab without reusing its old refresh token', async () => {
    const fresh = pair();
    writeAuthState({ ...useAuthStore.getState(), token:fresh.access_token, refreshToken:fresh.refresh_token });
    const fetchMock=vi.fn(); vi.stubGlobal('fetch',fetchMock);
    expect(await sessionToken()).toBe(fresh.access_token);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('surfaces rejected refresh credentials without retry loops or demo data', async () => {
    const fetchMock = vi.fn(async (url: string) => Response.json({ detail:'令牌已过期，请重新登录', path:url },{status:401}));
    vi.stubGlobal('fetch',fetchMock);
    await expect(callApi('/api/v1/assets',unavailable)).rejects.toMatchObject({status:401});
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(useAuthStore.getState().token).toBeNull();
    expect(useAuthStore.getState().sessionExpired).toBe(true);
  });

  it('returns legacy sessions without refresh credentials to the login screen on 401', async () => {
    useAuthStore.getState().setSession({ token: jwt(-3600), tenant,
      displayName: 'Legacy', role: 'owner', mustChangePassword: false });
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({}, { status: 401 })));
    await expect(callApi('/api/v1/assets', unavailable)).rejects.toMatchObject({ status: 401 });
    expect(useAuthStore.getState().token).toBeNull();
    expect(useAuthStore.getState().sessionExpired).toBe(true);
  });

  it('does not expire a newer login when an earlier request is rejected', async () => {
    let resolveResponse!: (response: Response) => void;
    const current = useAuthStore.getState();
    current.rotateTokens(current.sessionKey!, jwt(3600), 'refresh');
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(resolve => { resolveResponse = resolve; })));
    const pending = callApi('/api/v1/assets', unavailable);
    await vi.waitFor(() => expect(resolveResponse).toBeTypeOf('function'));
    useAuthStore.getState().setSession({ token: 'new-login', tenant,
      displayName: 'New', role: 'owner', mustChangePassword: false });
    resolveResponse(Response.json({}, { status: 401 }));
    await expect(pending).rejects.toMatchObject({ status: 401 });
    expect(useAuthStore.getState().token).toBe('new-login');
  });

  it('revokes the refresh token in the original tenant on logout', async () => {
    const fresh = pair();
    const current=useAuthStore.getState();
    current.rotateTokens(current.sessionKey!,fresh.access_token,fresh.refresh_token);
    current.setTenant({...tenant,id:'selected-tenant'});
    const fetchMock=vi.fn(async (_url: string,init?:RequestInit)=>{
      expect((init?.headers as Record<string,string>)['X-AGF-Tenant']).toBe('original-tenant');
      expect(JSON.parse(init?.body as string)).toEqual({refresh_token:'rotated-refresh'});
      return Response.json({status:'ok'});
    });
    vi.stubGlobal('fetch',fetchMock);
    await logoutSession();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(useAuthStore.getState().refreshToken).toBeNull();
    expect(localStorage.getItem('aigf.auth')).toBeNull();
  });

  it('does not clear credentials replaced by another browser tab', () => {
    const previous = useAuthStore.getState();
    writeAuthState({ ...previous, token: 'other-tab-token', refreshToken: 'other-tab-refresh' });
    previous.expireSession(previous.token!);
    expect(useAuthStore.getState().token).toBe('other-tab-token');
    expect(useAuthStore.getState().sessionExpired).toBe(false);
  });

  it('never stores refresh credentials for first-login or MFA enrollment sessions', () => {
    for (const flags of [{must_change_password:true},{mfa_enrollment_required:true}]) {
      expect(adaptLoginResponse({...flags,tokens:pair()}, {tenantSlug:'test',username:'test',password:''}).refreshToken).toBeUndefined();
    }
  });
});
