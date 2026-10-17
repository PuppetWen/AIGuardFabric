import type { Policy } from '@/types/domain';
import { policyWireAction } from './policyActions';

/** Restore server field names for structured conditions and policy scopes. */
function snakeKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(snakeKeys);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    key.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`), snakeKeys(item),
  ]));
}

export function policyBody(policy: Partial<Policy>): unknown {
  const language = policy.codeLanguage ?? policy.language;
  return snakeKeys({
    name: policy.name, description: policy.description, language,
    source: language === 'structured' ? policy.source ?? '' : policy.code, structured: language === 'structured' ? JSON.parse(policy.code || JSON.stringify(policy.structured ?? {})) : undefined,
    action: policyWireAction(policy.action),
    quotaId: policy.quotaId || undefined, degradeEndpointId: policy.degradeEndpointId || undefined,
    priority: policy.priority, interceptPoints: policy.interceptPoints,
    scopeAgentIds: policy.scopeAgentIds, scopeDepartments: policy.scopeDepartments,
    enabled: policy.enabled, dryRun: policy.dryRun,
    expectedVersion: policy.id ? policy.version : undefined,
  });
}
