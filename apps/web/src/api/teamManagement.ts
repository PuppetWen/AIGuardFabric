import { callApi } from './transport';
import type { TeamApplyRequest, TeamManagement, TeamOperation, TeamPreview,
  TeamPreviewRequest, TeamRequestContext, TeamUserDirectory, TeamUsersRequest } from '@/types/teamManagement';

const base = '/api/v1/alicloud/agentteams/team-management';
const unavailable = (): never => { throw new Error('Team management requires the backend / 团队维护需要连接后端'); };
const options = { noFallback: true, timeoutMs: 130_000 } as const;
const operationPath = (id: string) => `${base}/operations/${encodeURIComponent(id)}`;

export const teamManagementApi = {
  list: (requestId?: string) => callApi<TeamManagement>(base, unavailable,
    { noFallback: true, query: { request_id: requestId } }),
  observeUsers: (body: TeamUsersRequest) => callApi<TeamUserDirectory>(`${base}/users/observe`, unavailable,
    { ...options, method: 'POST', body }),
  preview: (body: TeamPreviewRequest) => callApi<TeamPreview>(`${base}/previews`, unavailable,
    { ...options, method: 'POST', body }),
  getPreview: (id: string) => callApi<TeamPreview>(`${base}/previews/${encodeURIComponent(id)}`, unavailable, options),
  apply: (body: TeamApplyRequest) => callApi<TeamOperation>(`${base}/operations`, unavailable,
    { ...options, method: 'POST', body }),
  getOperation: (id: string) => callApi<TeamOperation>(operationPath(id), unavailable, options),
  observe: (id: string, body: TeamRequestContext) => callApi<TeamOperation>(`${operationPath(id)}/observe`, unavailable,
    { ...options, method: 'POST', body }),
  publish: (id: string, body: TeamRequestContext) => callApi<TeamOperation>(`${operationPath(id)}/publish`, unavailable,
    { ...options, method: 'POST', body }),
};
