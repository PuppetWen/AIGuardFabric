import type { PolicyAction, QuotaUsage } from '@/types/domain';

/**
 * Label keys for every enum rendered in the UI. Pages call
 * `t(labelKey.policyAction(action))` so that adding an enum member in
 * `types/domain.ts` surfaces here as a compile error.
 */

export function policyActionKey(action: PolicyAction): string {
  return `policies.action.${action}`;
}

export function assetKindKey(kind: string): string {
  return `assets.kind.${kind}`;
}

export function severityKey(severity: string): string {
  return `severity.${severity}`;
}

export function domainKey(domain: string): string {
  return `domain.${domain}`;
}

export function lifecycleKey(lifecycle: string): string {
  return `assets.lifecycle.${lifecycle}`;
}

export function classificationKey(classification: string): string {
  return `assets.classification.${classification}`;
}

export function exposureKey(exposure: string): string {
  return `assets.exposure.${exposure}`;
}

export function healthKey(health: string): string {
  return `health.${health}`;
}

export function interceptPointKey(point: string): string {
  return `policies.intercept.${point}`;
}

export function quotaScopeKey(scope: string): string {
  return `runtime.quota.${scope}`;
}

export function ingestProtocolKey(protocol: string): string {
  return `ingest.protocol.${protocol}`;
}

export function parserEngineKey(engine: string): string {
  return `ingest.parsers.engine.${engine}`;
}

export function caseStateKey(state: string): string {
  return `cases.board.${state}`;
}

export function campaignStatusKey(status: string): string {
  return `status.${status}`;
}

export function attackCategoryKey(category: string): string {
  return `redteam.category.${category}`;
}

export function adapterCategoryKey(category: string): string {
  return `integrations.category.${category}`;
}

export function mcpTransportKey(transport: string): string {
  return `mcps.transport.${transport}`;
}

export function toolCapabilityKey(capability: string): string {
  return `mcps.capability.${capability}`;
}

export function managementModeKey(mode: string): string {
  return `agents.management.${mode}`;
}

export function userRoleKey(role: string): string {
  return `settings.users.role.${role}`;
}

export function reportTypeKey(type: string): string {
  return `reports.type.${type}`;
}

export function reportScheduleKey(schedule: string): string {
  return `reports.schedule.${schedule}`;
}

export function aliCloudServiceKey(service: string): string {
  return `alicloud.service.${service}`;
}

export function selfCheckCategoryKey(category: string): string {
  return `alicloud.selfcheck.category.${category}`;
}

export function selfCheckResultKey(result: string): string {
  return `alicloud.selfcheck.result.${result}`;
}

export function soarStatusKey(status: string): string {
  return `cases.soar.status.${status}`;
}

export function findingStatusKey(status: string): string {
  return `status.${status}`;
}

/* ------------------------------------------------------------------ */
/* Quota maths — shared by the runtime page and the unit tests         */
/* ------------------------------------------------------------------ */

export interface QuotaRatio {
  /** Raw used/limit ratio, unclamped (can exceed 1 when throttled). */
  ratio: number;
  /** Ratio as a whole-number percentage, unclamped. */
  percent: number;
  /** Ratio clamped to 0..1 for progress bars. */
  clampedRatio: number;
  level: 'normal' | 'warning' | 'exceeded';
}

/**
 * Compute the usage ratio of a quota.
 *
 * * `< 0.8`  → `normal`
 * * `< 1.0`  → `warning` (approaching the limit)
 * * `>= 1.0` → `exceeded`
 *
 * A zero or negative limit is treated as "no quota configured" and reported as
 * `normal` with a ratio of 0 so the UI does not divide by zero.
 */
export function quotaRatio(usage: Pick<QuotaUsage, 'used' | 'limit'>): QuotaRatio {
  const limit = usage.limit;
  if (!Number.isFinite(limit) || limit <= 0) {
    return { ratio: 0, percent: 0, clampedRatio: 0, level: 'normal' };
  }
  const used = Number.isFinite(usage.used) && usage.used > 0 ? usage.used : 0;
  const ratio = used / limit;
  const level: QuotaRatio['level'] = ratio >= 1 ? 'exceeded' : ratio >= 0.8 ? 'warning' : 'normal';
  return {
    ratio,
    percent: Math.round(ratio * 1000) / 10,
    clampedRatio: Math.min(1, Math.max(0, ratio)),
    level,
  };
}

/** Label key for a quota usage level. */
export function quotaLevelKey(level: QuotaRatio['level']): string {
  return `runtime.quota.${level}`;
}
