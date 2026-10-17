import type { InterceptPoint, PolicyAction } from '@/types/domain';
import { POLICY_ACTIONS } from '@/api/policyActions';

export const ACTIONS: readonly PolicyAction[] = POLICY_ACTIONS;
export const INTERCEPT_POINTS: InterceptPoint[] = ['mcp-proxy', 'ai-gateway', 'process-hook'];
export const MATCH_FIELDS = [
  'request.host',
  'request.tool',
  'request.command',
  'request.path',
  'request.bytes',
  'agent.id',
  'agent.department',
  'session.id',
  'session.classification',
];
export const OPERATORS = ['==', '!=', 'contains', 'startswith', 'matches', '>', '>=', '<', '<='];

/** Draft row in the form-mode condition builder. */
export interface ConditionRow {
  id: string;
  field: string;
  operator: string;
  value: string;
}
