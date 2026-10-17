import type { LoginRequest, LoginResponse, Tenant, UserRole } from '@/types/domain';

export interface AuthState {
  token: string | null;
  refreshToken: string | null;
  sessionTenantId: string | null;
  sessionKey: string | null;
  tenant: Tenant | null;
  displayName: string | null;
  role: UserRole | null;
  mustChangePassword: boolean;
}

export const AUTH_STORAGE_KEY = 'aigf.auth';

export const ANONYMOUS_AUTH: AuthState = {
  token: null,
  refreshToken: null,
  sessionTenantId: null,
  sessionKey: null,
  tenant: null,
  displayName: null,
  role: null,
  mustChangePassword: false,
};

export function readAuthState(): AuthState {
  try {
    const raw = window.localStorage.getItem(AUTH_STORAGE_KEY);
    if (!raw) {
      return ANONYMOUS_AUTH;
    }
    const parsed = JSON.parse(raw) as Partial<AuthState>;
    return {
      token: typeof parsed.token === 'string' ? parsed.token : null,
      refreshToken: typeof parsed.refreshToken === 'string' ? parsed.refreshToken : null,
      sessionTenantId: typeof parsed.sessionTenantId === 'string' ? parsed.sessionTenantId : parsed.tenant?.id ?? null,
      sessionKey: typeof parsed.sessionKey === 'string' ? parsed.sessionKey : null,
      tenant: (parsed.tenant as Tenant | null) ?? null,
      displayName: typeof parsed.displayName === 'string' ? parsed.displayName : null,
      role: (parsed.role as UserRole | null) ?? null,
      mustChangePassword: parsed.mustChangePassword === true,
    };
  } catch {
    return ANONYMOUS_AUTH;
  }
}

export function writeAuthState(state: AuthState): void {
  try {
    window.localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(state));
  } catch {
    /* storage unavailable — session stays in memory only */
  }
}

export function clearAuthState(): void {
  try {
    window.localStorage.removeItem(AUTH_STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

export type { LoginRequest, LoginResponse };
