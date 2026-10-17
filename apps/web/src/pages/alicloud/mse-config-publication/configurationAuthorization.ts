import type { CloudConfig } from '@/api/cloud';

const tuple = ['engine_origin', 'region_id', 'instance_id', 'namespace_id', 'config_group', 'config_data_id', 'config_dialect'];
const source = ['account_id', 'role_arn', 'ecs_role_name', 'oidc_provider_arn', 'sts_endpoint', 'external_id',
  'session_policy', 'expires_at', 'role_session_name'];
export function validOptionalEngineOrigin(value: unknown): boolean {
  if (value === undefined || value === '') return true;
  if (typeof value !== 'string' || value !== value.trim() || [...value].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) return false;
  try {
    const url = new URL(value), loopback = ['127.0.0.1', '[::1]'].includes(url.hostname);
    return !url.username && !url.password && !url.search && !url.hash && url.pathname === '/'
      && (url.protocol === 'https:' || (url.protocol === 'http:' && loopback));
  } catch { return false; }
}
export function publicationAuthorizationSettings(snapshot: CloudConfig, settings: Record<string, unknown>, mock: boolean,
  secrets: Record<string, unknown>, clear: string[]): Record<string, unknown> {
  if (snapshot.name !== 'alicloud-mse') return settings;
  const changed = [...tuple, ...source].some(key => snapshot.settings[key] !== settings[key])
    || (snapshot.settings.credential_source ?? 'access-key') !== (settings.credential_source ?? 'access-key')
    || (snapshot.settings.endpoint_style ?? 'public') !== (settings.endpoint_style ?? 'public')
    || (snapshot.settings.endpoint ?? '') !== (settings.endpoint ?? '')
    || (snapshot.settings.duration_seconds ?? 3600) !== (settings.duration_seconds ?? 3600)
    || snapshot.mock !== mock || clear.length > 0
    || Object.values(secrets).some(value => value !== '' && value !== null && value !== undefined);
  return changed ? { ...settings, managed_upsert_confirmed: false } : settings;
}
