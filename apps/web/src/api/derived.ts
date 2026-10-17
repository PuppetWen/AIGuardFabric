import type { QuotaUsage } from '@/types/domain';
import { quotaRatio } from '@/utils/labels';

/* ------------------------------------------------------------------ */
/* Derived helpers shared by pages                                     */
/* ------------------------------------------------------------------ */

export function summariseQuotas(usages: QuotaUsage[]): Record<QuotaUsage['scope'], number> {
  const result: Record<QuotaUsage['scope'], number> = { tenant: 0, agent: 0, session: 0 };
  for (const scope of ['tenant', 'agent', 'session'] as const) {
    const scoped = usages.filter((usage) => usage.scope === scope);
    if (scoped.length === 0) {
      continue;
    }
    const worst = scoped.reduce((acc, usage) => Math.max(acc, quotaRatio(usage).ratio), 0);
    result[scope] = Math.round(worst * 1000) / 10;
  }
  return result;
}
