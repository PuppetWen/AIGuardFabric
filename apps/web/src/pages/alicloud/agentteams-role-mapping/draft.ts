import type { Change, MappingDraft, MappingState, WorkerEvidence } from './types';
export function chooseWorker(state: MappingState, worker: WorkerEvidence): MappingDraft {
  const row = state.items.find(row => row.assetId === worker.assetId);
  return { worker: { ...worker }, expectedVersion: row?.version ?? 0, roleId: row?.proof.platformRoleId ?? '', confirmed: false };
}
export function adoptChange(state: MappingState, draft: MappingDraft): Change {
  const role = state.roles.find(role => role.id === draft.roleId && role.selectable);
  if (!state.catalogAvailable || !state.canManage || !draft.worker.assetId || !draft.worker.cloudRole || !role || !draft.confirmed
    || !Number.isSafeInteger(draft.expectedVersion) || draft.expectedVersion < 0) throw new Error('Choose actual Worker evidence and a supported tenant Role, then confirm / 选择真实成员与受支持角色后确认');
  return { action: 'adopt', configuration_version: draft.worker.configurationVersion, observed_at: draft.worker.observedAt,
    worker_name: draft.worker.workerName, team_name: draft.worker.teamName, cloud_role: draft.worker.cloudRole, role_id: role.id };
}
export function latestDraft(state: MappingState, draft: MappingDraft): MappingDraft | null {
  const worker = state.workers.find(row => row.assetId === draft.worker.assetId && row.teamName === draft.worker.teamName && row.workerName === draft.worker.workerName);
  if (!worker) return null;
  // Preserve the user's chosen Role; current directory validation remains mandatory before save.
  return { ...draft, worker: { ...worker }, expectedVersion: state.items.find(row => row.assetId === worker.assetId)?.version ?? 0, confirmed: false };
}
