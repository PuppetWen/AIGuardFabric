import type { AdapterHealthBar, DashboardOverview } from '@/types/domain';

import { demoAdapters } from './platform';

/**
 * Adapter health strip used by the overview dashboard.
 *
 * Kept separate from `platform.ts` so the dashboard can be tuned without
 * touching tenant/adapter configuration data.
 */
export const demoAssetHealth: AdapterHealthBar[] = demoAdapters.map((adapter, index) => ({
  id: adapter.id,
  name: adapter.name,
  category: adapter.category,
  health: adapter.health,
  uptimePercent:
    adapter.health === 'healthy'
      ? Math.round((99.4 + (index % 5) * 0.12) * 100) / 100
      : adapter.health === 'degraded'
        ? 97.42
        : adapter.health === 'unhealthy'
          ? 82.63
          : 0,
  mock: adapter.mock,
}));

/** Convenience alias used by the overview page. */
export type OverviewHealth = DashboardOverview['adapterHealth'];
