export type Eligibility = 'eligible' | 'revoked' | 'unverified' | 'disabled';
export interface PlatformRole {
  id: string; name: string; displayName: string; permissions: string[]; selectable: boolean; reason: string | null;
}
export interface WorkerEvidence {
  assetId: string | null; workerName: string; teamName: string; cloudRole: string | null;
  configurationVersion: number; observedAt: string;
}
export interface RoleConstraint {
  assetId: string; version: number; governed: boolean; eligibility: Eligibility; reason: string | null; updatedAt: string;
  proof: { configurationVersion: number; mocked: boolean; region: string; instanceId: string; workerName: string;
    teamName: string; cloudRole: string; observedAt: string; platformRoleId: string; department: string | null; dataClass: string };
  currentQualified: boolean | null; currentReason?: string | null; constraint: 'key_scopes_intersection'; cloudPermissionGranted: false;
}
export interface MappingState {
  catalogAvailable: boolean; canManage: boolean; roles: PlatformRole[]; items: RoleConstraint[];
  workers: WorkerEvidence[]; mappedCount: number; note: string;
  adoptionWindowSeconds?: number; permissionTTL?: null; providerCalled?: false;
  limits?: { workers: number; immutableIntents: number };
}
export interface MappingIntent {
  requestId: string; assetId: string; original: RoleConstraint; immutable: true; providerCalled: false;
}
export type Change = { action: 'disable' } | { action: 'adopt'; configuration_version: number; observed_at: string;
  worker_name: string; team_name: string; cloud_role: string; role_id: string };
export interface MappingInput { request_id: string; expected_version: number; confirm_local_constraint: true; change: Change }
export interface MappingDraft { worker: WorkerEvidence; roleId: string; expectedVersion: number; confirmed: boolean }
