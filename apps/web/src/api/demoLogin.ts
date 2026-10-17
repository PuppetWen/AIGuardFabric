import type { LoginRequest, LoginResponse, Tenant, User } from '@/types/domain';

import * as demo from './demo';

/* ------------------------------------------------------------------ */
/* Demo login                                                          */
/* ------------------------------------------------------------------ */

/** Credentials accepted by the offline demo login. */
export const DEMO_CREDENTIALS = {
  tenantSlug: 'acme',
  username: 'admin',
  password: 'Admin@12345',
  mfaCode: '123456',
} as const;

/**
 * Demo login. Mirrors the documented credential pair and always requests a
 * password change so the forced-change flow is exercised offline.
 */
export function demoLogin(payload: LoginRequest): LoginResponse {
  const user = demo.demoUsers.find(
    (candidate) =>
      candidate.username === payload.username &&
      candidate.tenantId ===
        (demo.demoTenants.find((tenant) => tenant.slug === payload.tenantSlug)?.id ?? 'ten-acme'),
  );
  const base = user ?? (demo.demoUsers[0] as User);
  const tenant =
    demo.demoTenants.find((candidate) => candidate.id === base.tenantId) ??
    (demo.demoTenants[0] as Tenant);
  const mustChange = payload.password === DEMO_CREDENTIALS.password;
  return {
    token: `demo.${btoa(`${tenant.slug}:${base.username}`).replace(/=+$/, '')}.${Date.now()}`,
    user: { ...base, mustChangePassword: mustChange || base.mustChangePassword },
    tenant,
    mustChangePassword: mustChange || base.mustChangePassword,
  };
}
