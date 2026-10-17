import type { CloudConfig } from '@/api/cloud';
const sourceKeys = ['region_id', 'account_id', 'role_arn', 'ecs_role_name', 'oidc_provider_arn',
  'sts_endpoint', 'external_id', 'session_policy', 'expires_at', 'role_session_name'];
const policyKeys = ['policy_http_api_id', 'policy_gateway_id', 'policy_environment_id', 'policy_id', 'policy_attachment_id', 'policy_dialect'];
const configurationKeys = ['configuration_kind', 'configuration_http_api_id', 'configuration_gateway_id', 'configuration_environment_id',
  'configuration_attachment_id', 'configuration_plugin_id', 'configuration_class_id', 'configuration_class_version'];
export function apigAuthorizationSettings(snapshot: CloudConfig, settings: Record<string, unknown>, mock: boolean,
  secrets: Record<string, unknown>, clear: string[]) {
  if (snapshot.name !== 'alicloud-apig') return settings;
  const changed = (keys: string[]) => keys.some(key => JSON.stringify(settings[key]) !== JSON.stringify(snapshot.settings[key]));
  const sourceChanged = snapshot.mock !== mock || changed(sourceKeys)
    || (settings.credential_source ?? 'access-key') !== (snapshot.settings.credential_source ?? 'access-key')
    || (settings.endpoint_style ?? 'public') !== (snapshot.settings.endpoint_style ?? 'public')
    || (settings.endpoint ?? '') !== (snapshot.settings.endpoint ?? '')
    || (settings.duration_seconds ?? 3600) !== (snapshot.settings.duration_seconds ?? 3600)
    || Object.values(secrets).some(value => typeof value === 'string' && value !== '') || clear.length > 0;
  const policyChanged = sourceChanged || changed(policyKeys);
  const configurationChanged = sourceChanged || changed(configurationKeys);
  if (!policyChanged && !configurationChanged) return settings;
  return { ...settings,
    ...(policyChanged ? { managed_policy_confirmed: false } : {}),
    ...(configurationChanged ? { managed_configuration_confirmed: false } : {}) };
}
