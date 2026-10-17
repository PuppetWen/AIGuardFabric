import type { PasswordPolicy } from '@/types/domain';

export const FALLBACK_POLICY: PasswordPolicy = {
  version: 0,
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireDigit: true,
  requireSymbol: true,
  maxAgeDays: 90,
  historySize: 5,
  lockoutThreshold: 5,
  mfaEnforced: true,
};

/** Evaluate the password policy and return `null` when the password is fine. */
export function checkPasswordPolicy(password: string, policy: PasswordPolicy): string | null {
  if (password.length < policy.minLength) return 'length';
  if (policy.requireUppercase && !/[A-Z]/.test(password)) return 'uppercase';
  if (policy.requireLowercase && !/[a-z]/.test(password)) return 'lowercase';
  if (policy.requireDigit && !/\d/.test(password)) return 'digit';
  if (policy.requireSymbol && !/[^A-Za-z0-9]/.test(password)) return 'symbol';
  return null;
}
