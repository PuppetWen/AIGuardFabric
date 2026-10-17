import { create } from 'zustand';

import type { Tenant, UserRole } from '@/types/domain';

import {
  ANONYMOUS_AUTH,
  clearAuthState,
  readAuthState,
  writeAuthState,
  type AuthState,
} from './authStorage';

/**
 * Global auth slice.
 *
 * `setSession` is called by `login()` (real or demo) and `reset()` by logout.
 * The API client reads `getState().token` rather than subscribing, so it stays
 * out of the React render path.
 */
export interface AuthSlice extends AuthState {
  sessionExpired: boolean;
  expireSession: (token: string) => void;
  sessionGeneration: number;
  role: UserRole | null;
  setSession: (session: {
    token: string;
    refreshToken?: string;
    tenant: Tenant;
    displayName: string;
    role: UserRole;
    mustChangePassword: boolean;
  }) => void;
  rotateTokens: (sessionKey: string, token: string, refreshToken: string) => boolean;
  setMustChangePassword: (value: boolean) => void;
  setRole: (role: UserRole) => void;
  setTenant: (tenant: Tenant) => void;
  reset: () => void;
}

const initial = readAuthState();

export const useAuthStore = create<AuthSlice>((set, get) => ({
  ...initial,
  sessionExpired: false,
  expireSession: (token) => {
    // A delayed failure from an old request must not clear a new login.
    if (get().token !== token) return;
    const stored = readAuthState();
    if (stored.token && stored.token !== token) {
      set({ ...stored, sessionExpired: false, sessionGeneration: get().sessionGeneration + 1 });
      return;
    }
    clearAuthState();
    set({ ...ANONYMOUS_AUTH, sessionExpired: true, sessionGeneration: get().sessionGeneration + 1 });
  },
  sessionGeneration: 1,
  role: (initial.role as UserRole | null) ?? null,
  setSession: ({ token, refreshToken, tenant, displayName, role, mustChangePassword }) => {
    const next: AuthState = { token, refreshToken: refreshToken ?? null, sessionTenantId: tenant.id,
      sessionKey: Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, '0')).join(''),
      tenant, displayName, role, mustChangePassword };
    writeAuthState(next);
    set({ ...next, role, sessionExpired: false, sessionGeneration: get().sessionGeneration + 1 });
  },
  rotateTokens: (sessionKey, token, refreshToken) => {
    if (get().sessionKey !== sessionKey) return false;
    writeAuthState({ ...get(), token, refreshToken });
    set({ token, refreshToken });
    return true;
  },
  setMustChangePassword: (value) => {
    writeAuthState({ ...get(), mustChangePassword: value });
    set({ mustChangePassword: value });
  },
  setRole: (role) => {
    writeAuthState({ ...get(), role });
    set({ role });
  },
  setTenant: (tenant) => {
    const current = get();
    const changed = current.tenant?.id !== tenant.id || current.tenant?.slug !== tenant.slug;
    writeAuthState({ ...current, tenant });
    // Advance on every actual switch, including A -> B -> A while a request awaits refresh.
    set({ tenant, sessionGeneration: current.sessionGeneration + (changed ? 1 : 0) });
  },
  reset: () => {
    clearAuthState();
    set({ ...ANONYMOUS_AUTH, sessionExpired: false, sessionGeneration: get().sessionGeneration + 1 });
  },
}));

/** Non-reactive token accessor used by the API client. */
export function currentToken(): string | null {
  return useAuthStore.getState().token ?? readAuthState().token;
}
