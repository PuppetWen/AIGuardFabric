import { callApi } from './transport';
import type { MappingInput, MappingIntent, MappingState, RoleConstraint } from '@/pages/alicloud/agentteams-role-mapping/types';
const base = '/api/v1/alicloud/agentteams/role-mappings';
const unavailable = (): never => { throw new Error('AgentTeams role constraints require the server / AgentTeams 角色约束需要服务端'); };
export const agentteamsRoleMappingApi = {
  state: (signal?: AbortSignal) => callApi<MappingState>(base, unavailable, { noFallback: true, signal }),
  current: (asset: string, signal?: AbortSignal) => callApi<RoleConstraint>(`${base}/${encodeURIComponent(asset)}`, unavailable, { noFallback: true, signal }),
  save: (asset: string, body: MappingInput, signal?: AbortSignal) => callApi<MappingIntent>(`${base}/${encodeURIComponent(asset)}`, unavailable,
    { method: 'PUT', body, noFallback: true, signal }),
  receipt: (asset: string, request: string, signal?: AbortSignal) => callApi<MappingIntent>(`${base}/${encodeURIComponent(asset)}/requests/${encodeURIComponent(request)}`,
    unavailable, { noFallback: true, signal }),
};
