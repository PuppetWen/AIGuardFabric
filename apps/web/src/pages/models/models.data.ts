import type { ModelRoutePolicy } from '@/types/domain';

export const ROUTE_STRATEGIES: ModelRoutePolicy['strategy'][] = [
  'priority',
  'weighted',
  'cost-first',
  'latency-first',
];
