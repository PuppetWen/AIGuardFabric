/** Rotate an expiring console session once, preserving the selected tenant and unsaved forms. */
import { useAuthStore } from '@/stores/authStore';
import { readAuthState } from '@/stores/authStorage';
import { API_BASE_URL } from './config';

let inFlight: Promise<string | null> | null = null;

function expiresSoon(token: string): boolean {
  try {
    const encoded = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(atob(encoded)) as { exp?: number };
    return typeof claims.exp === 'number' && claims.exp * 1000 <= Date.now() + 30000;
  } catch { return false; } // Opaque demo/API-key credentials do not have a refresh flow.
}

async function rotate(): Promise<string | null> {
  const current = useAuthStore.getState();
  const stored = readAuthState();
  if (stored.sessionKey && stored.sessionKey === current.sessionKey && stored.token && stored.refreshToken
    && stored.token !== current.token && !expiresSoon(stored.token)) {
    return current.rotateTokens(stored.sessionKey, stored.token, stored.refreshToken) ? stored.token : null;
  }
  if (!current.token || !current.refreshToken || !current.sessionTenantId || !current.sessionKey
    || current.mustChangePassword || !expiresSoon(current.token)) return current.token;
  const snapshot = { token: current.token, refresh: current.refreshToken, key: current.sessionKey, tenant: current.sessionTenantId };
  try {
    const response = await fetch(`${API_BASE_URL.replace(/\/$/, '')}/api/v1/auth/refresh`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-AGF-Tenant': snapshot.tenant },
      body: JSON.stringify({ refresh_token: snapshot.refresh }), credentials: 'same-origin',
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) return useAuthStore.getState().sessionKey === snapshot.key ? snapshot.token : null;
    const pair = await response.json() as { access_token?: string; refresh_token?: string };
    if (!pair.access_token || !pair.refresh_token) return snapshot.token;
    return useAuthStore.getState().rotateTokens(snapshot.key, pair.access_token, pair.refresh_token) ? pair.access_token : null;
  } catch { return useAuthStore.getState().sessionKey === snapshot.key ? snapshot.token : null; }
}

export async function sessionToken(): Promise<string | null> {
  const current = useAuthStore.getState();
  if (!current.token || !current.refreshToken || !expiresSoon(current.token)) return current.token;
  if (!inFlight) {
    // HTTPS browsers coordinate across tabs; the in-process promise also covers HTTP development mode.
    const operation = typeof navigator !== 'undefined' && navigator.locks
      ? navigator.locks.request('agf-refresh-session', rotate) : rotate();
    inFlight = operation.finally(() => { inFlight = null; });
  }
  return inFlight;
}

/** Local logout always completes; when online, revoke the server refresh token as well. */
export async function logoutSession(): Promise<void> {
  const before = useAuthStore.getState();
  try {
    const token = await sessionToken();
    const current = useAuthStore.getState();
    if (token && current.sessionKey === before.sessionKey && current.refreshToken && current.sessionTenantId) {
      await fetch(`${API_BASE_URL.replace(/\/$/, '')}/api/v1/auth/logout`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, 'X-AGF-Tenant': current.sessionTenantId },
        body: JSON.stringify({ refresh_token: current.refreshToken }), credentials: 'same-origin', signal: AbortSignal.timeout(5000),
      });
    }
  } catch { /* An offline logout still clears local credentials. */ }
  finally { if (useAuthStore.getState().sessionKey === before.sessionKey) useAuthStore.getState().reset(); }
}
