import { callApi } from './transport';

export interface CaseWorkflow {
  id: string; caseId: string; version: number; status: string; nextStep: number;
  playbook: { key: string; name: string; steps: { name: string; params?: unknown; action?: string; notify_channel?: string }[] };
  requestedBy: { id: string; kind: string }; executeAs: { id: string; kind: string }; separateApprover: boolean;
  trace: { name: string; outcome: string; note: string; error?: string }[];
  history: { at: string; actor: string; action: string; note: string; step: number; version: number }[];
  createdAt: string; updatedAt: string; deadlineAt?: string; wakeAt?: string; finishedAt?: string; reason?: string;
}
export interface WorkflowList {
  items: CaseWorkflow[]; total: number; canWrite: boolean; canApprove: boolean; actorId?: string; durable: boolean;
}
const unavailable = (): never => { throw new Error('剧本执行记录需要连接后端'); };
const url = (caseId: string) => `/api/v1/cases/${encodeURIComponent(caseId)}/playbook-runs`;
const options = { noFallback: true, opaqueKeys: ['playbook', 'context'] };
export const caseWorkflowsApi = {
  list: (caseId: string, page: number) => callApi<WorkflowList>(`${url(caseId)}?page=${page}&page_size=10`, unavailable, options),
  get: (caseId: string, id: string) => callApi<{run: CaseWorkflow}>(`${url(caseId)}/${encodeURIComponent(id)}`, unavailable, options),
  submit: (caseId: string, body: unknown) => callApi<{run: CaseWorkflow; durable: boolean}>(url(caseId), unavailable, { ...options, method: 'POST', body }),
  decide: (caseId: string, id: string, version: number, action: string, reason: string) =>
    callApi<{run: CaseWorkflow}>(`${url(caseId)}/${encodeURIComponent(id)}/decision`, unavailable,
      { ...options, method: 'POST', body: { expected_version: version, action, reason } }),
};
