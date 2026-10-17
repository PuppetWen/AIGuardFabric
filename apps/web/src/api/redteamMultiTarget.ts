import { callApi } from './transport';
export interface MultiProfile { id: string; assetId: string; name: string; enabled: boolean; version: number }
export interface MultiSelection { kind: 'agent-http' | 'mcp-http'; profile_id: string; expected_version: number }
export interface MultiPreview { topologySha256: string; requiresDatabase: boolean; topology: Record<string, unknown> }
export interface MultiRun {
  requestId: string; status: 'running' | 'uncertain' | 'completed' | 'failed' | 'cancelled' | 'archived';
  generation: number; archivedAt: string | null; originalStatus: string | null;
  completionState: 'in_progress' | 'pending_audit' | 'complete'; sourceCurrent: boolean | null;
  evidence: Array<{ step: number; completed: boolean; protectedCanaryObserved: boolean | null; responseSha256: string | null }>;
  findingIds: string[]; auditId: string | null; defensePassed: boolean | null; localFixture: boolean; externalDefenseVerified: false;
}
export interface MultiExecute { request_id: string; targets: MultiSelection[]; reviewed_topology_sha256: string; confirm_registered_targets: boolean; confirm_live: boolean }
export interface MultiRecent { items: Array<Pick<MultiRun, 'requestId' | 'status' | 'completionState' | 'generation' | 'originalStatus'> & { archived: boolean }>; total: number; offset: number; limit: number; truncated: boolean; completeHistory: false }
export type McpRevision = '2026-07-28' | '2025-11-25';
export interface ManagedSettings { kind: MultiSelection['kind']; profileId: string; profileVersion: number; version: number; url: string; enabled: boolean; mcpProtocolRevision: McpRevision; privateNetwork: { addresses: string[]; port: number; allowPlainHttp: boolean } | null }
export interface ManagedView { configured: boolean; profileId: string; profileVersion: number; url: string; version: number; settings: ManagedSettings | null }
export interface ManagedInput { expected_version: number; profile_version: number; url: string; enabled: boolean; mcp_protocol_revision: McpRevision; private_network: { addresses: string[]; port: number; allow_plain_http: boolean; confirm_exact_private_network: boolean } | null }
const ROOT = '/api/v1/redteam/multi-target';
export const multiTargetApi = {
  recent: async (offset = 0, signal?: AbortSignal) => (await callApi<MultiRecent>(ROOT + '/runs?limit=20&offset=' + offset, () => null as never, { noFallback: true, signal })).data,
  archive: async (id: string, generation: number, signal?: AbortSignal) => (await callApi<MultiRun>(ROOT + '/runs/' + encodeURIComponent(id) + '/archive', () => null as never, { method: 'POST', body: { expected_generation: generation }, noFallback: true, signal })).data,
  managed: async (kind: MultiSelection['kind'], id: string, signal?: AbortSignal) => (await callApi<ManagedView>(ROOT + '/profiles/' + kind + '/' + encodeURIComponent(id) + '/transport', () => null as never, { noFallback: true, signal })).data,
  saveManaged: async (kind: MultiSelection['kind'], id: string, body: ManagedInput, signal?: AbortSignal) => (await callApi<ManagedSettings>(ROOT + '/profiles/' + kind + '/' + encodeURIComponent(id) + '/transport', () => null as never, { method: 'PUT', body, noFallback: true, signal })).data,
  profiles: async (kind: 'agent' | 'mcp', signal?: AbortSignal) => (await callApi<{ items: MultiProfile[] }>(`/api/v1/redteam/${kind}-targets`, () => null as never, { noFallback: true, signal })).data,
  preview: async (targets: MultiSelection[], signal?: AbortSignal) => (await callApi<MultiPreview>(`${ROOT}/preview`, () => null as never, { method: 'POST', body: { targets }, noFallback: true, signal })).data,
  execute: async (body: MultiExecute, signal?: AbortSignal) => (await callApi<MultiRun>(`${ROOT}/runs`, () => null as never, { method: 'POST', body, noFallback: true, timeoutMs: 120_000, signal })).data,
  get: async (id: string, signal?: AbortSignal) => (await callApi<MultiRun>(`${ROOT}/runs/${encodeURIComponent(id)}`, () => null as never, { noFallback: true, signal })).data,
  local: async (id: string, action: 'cancel' | 'recover', signal?: AbortSignal) => (await callApi<MultiRun>(`${ROOT}/runs/${encodeURIComponent(id)}/${action}`, () => null as never, { method: 'POST', body: {}, noFallback: true, signal })).data,
};
