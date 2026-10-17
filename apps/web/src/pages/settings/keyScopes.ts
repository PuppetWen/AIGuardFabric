export const AVAILABLE_SCOPES = [
  'assets:read', 'assets:write', 'agents:read', 'agents:write', 'mcps:read', 'mcps:write', 'mcps:execute',
  'models:read', 'models:write', 'findings:read', 'redteam:write', 'ingest:write',
  'reports:read', 'policies:read', 'policies:write', 'sources:read', 'sources:write',
  'quotas:read', 'quotas:write', 'alicloud:read', 'alicloud:write', 'alerts:read',
];

export function validKeyScopes(scopes: string[]): string[] {
  return [...new Set(scopes.filter(scope => AVAILABLE_SCOPES.includes(scope)))];
}
