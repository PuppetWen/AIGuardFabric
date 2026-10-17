import type { ManagedTeam, TeamAction, TeamChange, TeamManagement, TeamOperation, TeamPreview } from '@/types/teamManagement';

export interface TeamDraftValues {
  action: TeamAction;
  teamName: string;
  description: string;
  changeDescription: boolean;
  replaceMembers: boolean;
  memberNames: string[];
  adminName?: string;
  deleteName: string;
  acknowledgeCleanup: boolean;
}
export function initialTeamDraft(action: TeamAction, team?: ManagedTeam): TeamDraftValues {
  return { action, teamName: action === 'create' ? '' : team?.teamName ?? '',
    description: action === 'create' ? '' : team?.description ?? '', changeDescription: action === 'create',
    replaceMembers: false, memberNames: action === 'create' ? [] : [...(team?.memberNames ?? [])],
    deleteName: '', acknowledgeCleanup: false };
}
export function teamChange(draft: TeamDraftValues, team?: ManagedTeam): TeamChange | undefined {
  if (!draft.teamName.trim() || [...draft.teamName].some(char => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127)
    || draft.teamName.length > 128 || team?.busy || team?.unresolvedDelete) return;
  if (draft.action === 'create') return { action: 'create', team_name: draft.teamName,
    description: draft.description, member_names: [...draft.memberNames],
    ...(draft.adminName ? { admin_name: draft.adminName } : {}) };
  if (!team?.currentAvailable || team.busy || team.unresolvedDelete || team.teamName !== draft.teamName) return;
  if (draft.action === 'delete') return draft.acknowledgeCleanup && draft.deleteName === draft.teamName
    ? { action: 'delete', team_name: draft.teamName, confirm_team_name: draft.deleteName, confirm_async_cleanup: true } : undefined;
  if (!draft.changeDescription && !draft.replaceMembers) return;
  if (draft.replaceMembers && (!team.memberNamesAvailable || !Array.isArray(team.memberNames))) return;
  return { action: 'update', team_name: draft.teamName,
    ...(draft.changeDescription ? { description: draft.description } : {}),
    ...(draft.replaceMembers ? { members: { mode: 'replace' as const, names: [...draft.memberNames], confirm_full_replacement: true as const } } : {}) };
}
export function currentTeamPreview(preview: TeamPreview, data: TeamManagement, now: number): boolean {
  const team = data.items.find(item => item.teamName === preview.teamName);
  return data.enabled && data.inventoryAvailable && preview.previewUsable && preview.baselineComplete
    && preview.scopeId === data.scopeId && preview.configurationVersion === data.configurationVersion
    && preview.mocked === data.mocked && preview.instanceId === data.instanceId
    && Date.parse(preview.expiresAt) > now && !(team?.busy || team?.unresolvedDelete)
    && preview.expectedStateVersion === (team?.stateVersion ?? 0);
}
export function currentTeamRecovery(operation: TeamOperation, data: TeamManagement): boolean {
  return data.scopeId !== null && operation.recoveryScopeId === data.scopeId
    && operation.recoveryConfigurationVersion === data.configurationVersion
    && operation.mocked === data.mocked && operation.status !== 'superseded';
}
