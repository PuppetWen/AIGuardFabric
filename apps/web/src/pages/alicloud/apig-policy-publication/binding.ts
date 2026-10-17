import type { CloudConfig } from '@/api/cloud';
export const dialect = 'apig-2024-03-27-ai-token-rate-limit';
export const fields = ['policy_http_api_id', 'policy_gateway_id', 'policy_environment_id', 'policy_id', 'policy_attachment_id'] as const;
export type BindingField = typeof fields[number];
export interface BindingDraft { enabled: boolean; mock: boolean; region: string; ids: Record<BindingField, string>; confirmed: boolean }
const setting = (config: CloudConfig, key: string) => typeof config.settings[key] === 'string' ? config.settings[key] as string : '';
export function bindingDraft(config: CloudConfig): BindingDraft {
  return { enabled: config.enabled, mock: config.mock, region: setting(config, 'region_id'), confirmed: false,
    ids: { policy_http_api_id: setting(config, fields[0]), policy_gateway_id: setting(config, fields[1]), policy_environment_id: setting(config, fields[2]),
      policy_id: setting(config, fields[3]), policy_attachment_id: setting(config, fields[4]) } };
}
export function bindingBody(config: CloudConfig, draft: BindingDraft) {
  if (!Number.isSafeInteger(config.version) || config.version < 0) throw new Error('配置版本未知 / Configuration revision unknown');
  if ([draft.region, ...fields.map(key => draft.ids[key])].some(value => !value || value !== value.trim()
    || new TextEncoder().encode(value).length > 256 || [...value].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
    || value.includes('/') || value.includes('\\') || value === '.' || value === '..'))
    throw new Error('请明确填写真实地域和五项 ID，不含路径、空白或控制字符 / Enter the actual region and five IDs without path separators, surrounding whitespace or control characters');
  if (!draft.confirmed) throw new Error('请明确确认管理既有限流策略且共享影响未知 / Explicitly confirm management of the existing rate-limit policy and its unknown shared impact');
  return { expected_version: config.version, enabled: draft.enabled, mock: draft.mock,
    settings: { ...config.settings, region_id: draft.region, ...draft.ids, policy_dialect: dialect, managed_policy_confirmed: true },
    secrets: {}, clear_secrets: [] };
}
export function mockExample(draft: BindingDraft): BindingDraft {
  return { ...draft, confirmed: false, region: 'cn-hangzhou', ids: { policy_http_api_id: 'api-agf-demo', policy_gateway_id: 'gw-agf-demo',
    policy_environment_id: 'env-agf-demo', policy_id: 'policy-agf-demo', policy_attachment_id: 'attachment-agf-demo' } };
}
