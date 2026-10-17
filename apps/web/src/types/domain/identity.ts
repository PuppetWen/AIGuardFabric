import type { IsoTimestamp } from './common';

/* ------------------------------------------------------------------ */
/* Tenancy & identity                                                  */
/* ------------------------------------------------------------------ */

export interface Tenant {
  version: number;
  directoryVersion?: number;
  directoryName?: string;
  enabled?: boolean;
  id: string;
  slug: string;
  name: string;
  plan: 'community' | 'standard' | 'enterprise';
  region: string;
  whiteLabel: WhiteLabel;
  quotaDefaults: QuotaDefaults;
  createdAt: IsoTimestamp;
}

export interface WhiteLabel {
  productName: string;
  logoText: string;
  primaryColor: string;
  favicon?: string;
}

export interface QuotaDefaults {
  version: number;
  tenantTokensPerDay: number;
  agentTokensPerHour: number;
  sessionTokensPerTurn: number;
  maxConcurrentSessions: number;
}

export type UserRole = 'owner' | 'admin' | 'analyst' | 'responder' | 'auditor' | 'viewer';

export interface User {
  version: number;
  identityProvider?: string;
  id: string;
  tenantId: string;
  username: string;
  displayName: string;
  email: string;
  role: UserRole;
  mfaEnabled: boolean;
  mustChangePassword: boolean;
  lastLoginAt: IsoTimestamp;
  status: 'active' | 'locked' | 'disabled';
}

export interface ApiKey {
  boundAgentId?: string | null;
  id: string;
  tenantId: string;
  name: string;
  prefix: string;
  scopes: string[];
  createdAt: IsoTimestamp;
  expiresAt: IsoTimestamp | null;
  lastUsedAt: IsoTimestamp | null;
  revoked: boolean;
}

export interface PasswordPolicy {
  version: number;
  requireClasses?: boolean;
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireDigit: boolean;
  requireSymbol: boolean;
  maxAgeDays: number;
  historySize: number;
  lockoutThreshold: number;
  mfaEnforced: boolean;
}

export interface LoginRequest {
  tenantSlug: string;
  username: string;
  password: string;
  mfaCode?: string;
}

export interface LoginResponse {
  refreshToken?: string;
  passwordPolicy?: PasswordPolicy;
  mfaEnrollmentRequired?: boolean;
  token: string;
  user: User;
  tenant: Tenant;
  mustChangePassword: boolean;
}

export interface ChangePasswordRequest {
  tenantSlug: string;
  username: string;
  currentPassword: string;
  newPassword: string;
}
