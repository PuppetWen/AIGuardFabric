import type { CloudConfig } from '@/api/cloud';
export interface BindingDraft {
  enabled: boolean; mock: boolean; origin: string; region: string; instance: string;
  namespaceMode: 'default' | 'specific' | undefined; namespace: string;
  group: string; dataId: string; confirmed: boolean;
}
const setting = (config: CloudConfig, name: string) => typeof config.settings[name] === 'string' ? config.settings[name] as string : '';
const control = (value: string) => [...value].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127);
export function bindingDraft(config: CloudConfig): BindingDraft {
  const namespace = config.settings.namespace_id;
  return { enabled: config.enabled, mock: config.mock, origin: setting(config, 'engine_origin'),
    region: setting(config, 'region_id'), instance: setting(config, 'instance_id'),
    namespaceMode: typeof namespace !== 'string' ? undefined : namespace === '' ? 'default' : 'specific',
    namespace: typeof namespace === 'string' ? namespace : '', group: setting(config, 'config_group'),
    dataId: setting(config, 'config_data_id'), confirmed: false };
}
export function bindingBody(config: CloudConfig, draft: BindingDraft) {
  if (!Number.isSafeInteger(config.version) || config.version < 0) throw new Error('配置版本未知 / Configuration version is unknown');
  const raw = [draft.region, draft.instance, draft.group, draft.dataId];
  if (raw.some(value => !value || value !== value.trim() || control(value) || new TextEncoder().encode(value).length > 256))
    throw new Error('地域、实例、Group 与 Data ID 必须明确，不能包含首尾空白或控制字符。 / Region, instance, group and Data ID must be explicit without surrounding whitespace or control characters.');
  if (!draft.namespaceMode || (draft.namespaceMode === 'specific' && (!draft.namespace || draft.namespace !== draft.namespace.trim() || control(draft.namespace))))
    throw new Error('请明确选择默认命名空间或提供真实 namespace ID。 / Explicitly select the default namespace or provide its actual ID.');
  if (draft.origin !== draft.origin.trim() || control(draft.origin)) throw new Error('引擎 origin 不能含空白或控制字符 / Engine origin cannot contain surrounding whitespace or control characters');
  let url: URL;
  try { url = new URL(draft.origin); } catch { throw new Error('引擎 origin 无效 / Invalid engine origin'); }
  const loopback = ['127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/'
    || (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)))
    throw new Error('请填写独立 HTTPS origin，不含路径或凭据。HTTP 仅服务端授权的字面 loopback 测试可用。 / Use a separate HTTPS origin without path or credentials. HTTP requires a server-authorized literal loopback test.');
  if (draft.enabled && !draft.mock && !config.environmentMock && config.settings.engine_origin !== url.origin)
    throw new Error('真实启用连接更换引擎地址需新凭据。请先明确停用，或在连接配置同次保存新 engine origin 与适用凭据，再回此处确认。不会自动停用或切换 Mock。 / Retargeting an enabled Live connection requires new credentials. Explicitly disable it first, or save the new engine origin and appropriate credentials together in Connection configuration, then return to confirm. The mode and enabled state are not changed automatically.');
  if (!draft.confirmed) throw new Error('请明确确认管理此专用 Data ID 的 MD5 upsert。 / Explicitly confirm MD5 upsert management of this dedicated Data ID.');
  return { expected_version: config.version, enabled: draft.enabled, mock: draft.mock,
    settings: { ...config.settings, engine_origin: url.origin, region_id: draft.region, instance_id: draft.instance,
      namespace_id: draft.namespaceMode === 'default' ? '' : draft.namespace, config_group: draft.group,
      config_data_id: draft.dataId, config_dialect: 'nacos-http-v2-cas', managed_upsert_confirmed: true },
    secrets: {}, clear_secrets: [] };
}
