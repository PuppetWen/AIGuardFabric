import { callApi } from './transport';

export interface PlaybookDefinition {
  key: string; name: string; description?: string; enabled?: boolean; require_approval?: boolean; timeout_secs?: number;
  trigger: { min_severity?: string; domains?: string[]; rule_keys?: string[]; asset_kinds?: string[]; condition?: string };
  steps: { name: string; action?: string; params?: Record<string, unknown>; [key: string]: unknown }[];
  [key: string]: unknown;
}
export interface Automation {
  id: string; playbook: PlaybookDefinition; enabled: boolean; separateApprover: boolean; version: number; since: string;
  history: { version: number; at: string; actor: string; note: string; playbook: PlaybookDefinition; enabled: boolean; separateApprover: boolean }[];
}
export interface TriggerDelivery {
  id: string; automationVersion: number; alertId: string; alertTitle: string; status: string; reason: string;
  caseId?: string; runId?: string; attempts: number; at: string;
  history: {at: string; actor: string; status: string; reason: string}[];
}
export interface AutomationPreview {
  matches: boolean; active: boolean; requiresApproval: boolean;
  context: { asset_ids: string[]; finding_ids: string[]; rule_keys: string[]; params: Record<string, string> }; steps: string[];
}
const root = '/api/v1/soar/automations';
const unavailable = (): never => { throw new Error('自动响应需要连接后端 / Automatic response requires the server'); };
const options = { noFallback: true, opaqueKeys: ['playbook', 'context'] };
export const automationsApi = {
  get: (id: string) => callApi<{automation: Automation}>(`${root}/${encodeURIComponent(id)}`, unavailable, options),
  list: (page: number, keyword: string) => callApi<{items: Automation[]; total: number; canManage: boolean; durable: boolean}>(root, unavailable,
    { ...options, query: { page, pageSize: 10, keyword } }),
  templates: () => callApi<{items: {key: string; nameZh: string; nameEn: string; playbook: PlaybookDefinition}[]}>(`${root}/templates`, unavailable, options),
  save: (id: string | undefined, body: unknown) => callApi<{automation: Automation}>(id ? `${root}/${encodeURIComponent(id)}` : root, unavailable,
    { ...options, method: id ? 'PUT' : 'POST', body }),
  preview: (body: unknown) => callApi<AutomationPreview>(`${root}/preview`, unavailable, { ...options, method: 'POST', body }),
  deliveries: (id: string, page: number, keyword: string) => callApi<{items: TriggerDelivery[]; total: number}>(`${root}/${encodeURIComponent(id)}/deliveries`, unavailable,
    { ...options, query: { page, pageSize: 10, keyword } }),
  retry: (id: string, delivery: string, version: number) => callApi(`${root}/${encodeURIComponent(id)}/deliveries/${encodeURIComponent(delivery)}/retry`, unavailable,
    { ...options, method: 'POST', body: { expected_version: version } }),
};
