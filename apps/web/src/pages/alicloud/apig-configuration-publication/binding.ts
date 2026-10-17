import type { CloudConfig } from '@/api/cloud';
export const commonFields = ['configuration_http_api_id', 'configuration_gateway_id', 'configuration_environment_id'] as const;
export const contentFields = ['configuration_attachment_id', 'configuration_plugin_id', 'configuration_class_id', 'configuration_class_version'] as const;
export const fields = [...commonFields, ...contentFields] as const;
export type BindingField = typeof fields[number];
export interface BindingDraft { enabled: boolean; mock: boolean; region: string; kind: 'content' | 'models' | null; ids: Record<BindingField, string>; confirmed: boolean }
const setting = (config: CloudConfig, key: string) => typeof config.settings[key] === 'string' ? config.settings[key] as string : '';
export function bindingDraft(config: CloudConfig): BindingDraft {
  const kind = setting(config, 'configuration_kind');
  return { enabled: config.enabled, mock: config.mock, region: setting(config, 'region_id'), kind: kind === 'content' || kind === 'models' ? kind : null,
    confirmed: false, ids: Object.fromEntries(fields.map(field => [field, setting(config, field)])) as Record<BindingField, string> };
}
export function bindingBody(config: CloudConfig, draft: BindingDraft) {
  if (!Number.isSafeInteger(config.version) || config.version < 0) throw new Error('配置版本未知 / Configuration revision unknown');
  if (!draft.kind) throw new Error('请明确选择内容安全或模型配置 / Explicitly choose content security or model configuration');
  const needed = draft.kind === 'content' ? fields : commonFields;
  if ([draft.region, ...needed.map(key => draft.ids[key])].some(value => !value || value !== value.trim()
    || new TextEncoder().encode(value).length > 256 || [...value].some(c => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
    || value.includes('/') || value.includes('\\') || value === '.' || value === '..'))
    throw new Error('请填写真实地域与既有资源 ID / Enter the actual region and existing resource IDs');
  if (!draft.confirmed) throw new Error('请明确确认受管公开配置及未知共享影响 / Explicitly confirm public-field management and unknown shared impact');
  return { expected_version: config.version, enabled: draft.enabled, mock: draft.mock,
    settings: { ...config.settings, region_id: draft.region, configuration_kind: draft.kind, ...draft.ids, managed_configuration_confirmed: true },
    secrets: {}, clear_secrets: [] };
}
export function mockExample(draft: BindingDraft): BindingDraft {
  if (!draft.kind) return draft;
  return { ...draft, confirmed: false, region: 'cn-hangzhou', ids: { configuration_http_api_id: 'api-owned', configuration_gateway_id: 'gw-owned',
    configuration_environment_id: 'env-owned', configuration_attachment_id: 'pa-owned', configuration_plugin_id: 'pl-owned',
    configuration_class_id: 'cls-owned', configuration_class_version: '1.0.0' } };
}
