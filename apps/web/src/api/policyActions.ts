import type { PolicyAction } from '@/types/domain';

/** Policy management preserves distinct enforcement verbs; quota is never throttle. */
export const POLICY_ACTIONS = ['allow', 'deny', 'alert', 'mask', 'redirect', 'throttle', 'quota',
  'quarantine', 'approval', 'circuit-break'] as const satisfies readonly PolicyAction[];
export function isPolicyAction(value: unknown): value is Exclude<PolicyAction, 'unknown'> {
  return typeof value === 'string' && (POLICY_ACTIONS as readonly string[]).includes(value);
}
export function normalizePolicyAction(value: unknown): PolicyAction {
  if (isPolicyAction(value)) return value;
  const aliases: Record<string, PolicyAction> = { audit: 'alert', redact: 'mask', degrade: 'redirect',
    isolate: 'quarantine', circuitbreak: 'circuit-break' };
  return typeof value === 'string' && Object.hasOwn(aliases, value) ? aliases[value] ?? 'unknown' : 'unknown';
}
export function policyWireAction(value: unknown): string {
  if (!isPolicyAction(value)) throw new Error('策略动作未知，不能发布；请核对服务端版本 / Unknown policy action; verify the server version before publishing');
  const aliases: Partial<Record<Exclude<PolicyAction, 'unknown'>, string>> = {
    alert: 'audit', mask: 'redact', redirect: 'degrade', quarantine: 'isolate',
  };
  return aliases[value] ?? value;
}
