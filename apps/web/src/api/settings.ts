import type { User, UserRole, Tenant, QuotaDefaults, PasswordPolicy } from '@/types/domain';
import { callApi } from './transport';

function unavailable(): never { throw new Error('此操作需要连接到真实后端'); }

export interface NewUser {
  username: string;
  display_name: string;
  email: string;
  password: string;
  role: UserRole;
}

export const settingsApi = {
  savePasswordPolicy: (policy: PasswordPolicy, expectedVersion: number) => callApi<PasswordPolicy>('/api/v1/settings/password-policy', unavailable,
    { method: 'PUT', noFallback: true, body: { expected_version: expectedVersion,
      min_length: policy.minLength, require_classes: policy.requireClasses ?? false,
      require_uppercase: policy.requireUppercase, require_lowercase: policy.requireLowercase, require_digit: policy.requireDigit,
      require_symbol: policy.requireSymbol, max_age_days: policy.maxAgeDays, history_size: policy.historySize,
      lockout_threshold: policy.lockoutThreshold, mfa_enforced: policy.mfaEnforced } }),
  saveTenant: (body: Tenant, expectedVersion: number) => callApi<Tenant>('/api/v1/settings/tenant', unavailable,
    { method: 'PUT', noFallback: true, body: { expectedVersion, name: body.name, plan: body.plan,
      region: body.region, whiteLabel: body.whiteLabel } }),
  saveQuotas: (body: QuotaDefaults, expectedVersion: number) => callApi<QuotaDefaults>('/api/v1/settings/quotas', unavailable,
    { method: 'PUT', noFallback: true, body: { expectedVersion,
      tenantTokensPerDay: body.tenantTokensPerDay, agentTokensPerHour: body.agentTokensPerHour,
      sessionTokensPerTurn: body.sessionTokensPerTurn, maxConcurrentSessions: body.maxConcurrentSessions } }),
  createUser: (body: NewUser) =>
    callApi<User>('/api/v1/users', unavailable, { method: 'POST', body, noFallback: true }),
  updateUser: (id: string, body: { expected_version: number; role?: UserRole; status?: User['status'] }) =>
    callApi<User>(`/api/v1/users/${encodeURIComponent(id)}`, unavailable,
      { method: 'PATCH', body, noFallback: true }),
  createKey: (body: { name: string; scopes: string[]; expires_in_secs: number; bound_agent_id?: string }) =>
    callApi<{ plaintext: string }>('/api/v1/settings/api-keys', unavailable,
      { method: 'POST', body, noFallback: true }),
  revokeKey: (id: string) =>
    callApi<{ revoked: boolean }>(`/api/v1/settings/api-keys/${encodeURIComponent(id)}`, unavailable,
      { method: 'DELETE', noFallback: true }),
};
