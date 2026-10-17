export type TeamAction = 'create' | 'update' | 'delete';
export type TeamOperationStatus = 'started' | 'deleting' | 'verified' | 'failed' | 'uncertain' | 'superseded';
export type TeamRecoveryAction = 'read_receipt' | 'observe' | 'retry_inventory';

export interface TeamUserOption {
  name: string;
  displayName: string | null;
  status: string | null;
  existenceVerified: boolean;
  adminEligibility: null;
}

export interface TeamUserDirectory {
  snapshotId: string;
  configurationVersion: number;
  scopeId: string;
  mocked: boolean;
  instanceId: string;
  observedAt: string;
  query: { nameLike: string | null };
  pageComplete: boolean;
  complete: boolean;
  directoryComplete: boolean;
  nextCursor: string | null;
  totalCount: number | null;
  selectionUsable: boolean;
  unusableReason: string | null;
  items: TeamUserOption[];
}

export interface ManagedTeam {
  teamName: string;
  stateVersion: number;
  busy: boolean;
  unresolvedDelete: boolean;
  currentAvailable: boolean;
  description: string | null;
  memberNames: string[] | null;
  memberNamesAvailable: boolean;
  adminName: string | null;
  leaderName: string | null;
  workerNames: string[] | null;
  relationshipAvailable: boolean;
}

export type TeamChange =
  | { action: 'create'; team_name: string; description?: string; member_names: string[]; admin_name?: string }
  | { action: 'update'; team_name: string; description?: string;
      members?: { mode: 'replace'; names: string[]; confirm_full_replacement: true } }
  | { action: 'delete'; team_name: string; confirm_team_name: string; confirm_async_cleanup: true };

export interface TeamRequestContext {
  request_id: string;
  configuration_version: number;
  confirm_live: boolean;
}
export interface TeamUsersRequest extends TeamRequestContext { name_like?: string; cursor?: string }
export interface TeamPreviewRequest extends TeamRequestContext {
  expected_state_version: number;
  user_snapshot_id?: string;
  change: TeamChange;
}
export interface TeamApplyRequest extends TeamRequestContext {
  preview_id: string;
  expected_state_version: number;
  confirm_apply: true;
}

export interface TeamPreview {
  id: string;
  action: TeamAction;
  scopeId: string;
  configurationVersion: number;
  mocked: boolean;
  region: string;
  instanceId: string;
  teamName: string;
  expectedStateVersion: number;
  baselineObservedAt: string;
  baselineComplete: boolean;
  baselineHash: string;
  descriptionChanged: boolean;
  membersChanged: boolean;
  before: {
    description: string | null;
    memberNames: string[] | null;
    memberNamesAvailable: boolean;
    adminName: string | null;
    leaderName: string | null;
    workerNames: string[] | null;
    workerNamesAvailable: boolean;
  };
  desired: { description?: string; memberNames?: string[]; adminName?: string };
  addedMembers: string[];
  removedMembers: string[];
  verifiedUsers: TeamUserOption[];
  deleteImpact?: { workerCount: number | null; humanCount: number | null;
    roomCount: number | null; taskCount: number | null; asyncCleanup: true } | null;
  expiresAt: string;
  previewUsable: boolean;
  unusableReason: string | null;
}

export interface TeamOperation {
  id: string;
  requestId: string;
  previewId: string;
  action: TeamAction;
  teamName: string;
  scopeId: string;
  configurationVersion: number;
  mocked: boolean;
  status: TeamOperationStatus;
  recoveryScopeId: string | null;
  recoveryConfigurationVersion: number | null;
  startedAt: string;
  finishedAt: string | null;
  leaseExpiresAt: string | null;
  busy: boolean;
  cloudWrite: {
    status: 'not_started' | 'attempting' | 'accepted' | 'rejected' | 'unknown' | 'skipped';
    receiptId: string | null;
    providerRequestId: string | null;
    providerCode: string | null;
    httpStatus: number | null;
  };
  readback: {
    status: 'pending' | 'matched' | 'deleting' | 'absent' | 'mismatch' | 'unknown';
    observedAt: string | null;
    resourceState: 'present' | 'absent' | 'unknown';
    matchedFields: string[];
    conflictFields: string[];
  };
  inventoryPublish: {
    status: 'not_started' | 'published' | 'failed' | 'unknown' | 'superseded';
    checkedAt: string | null;
    errorCode: string | null;
  };
  safeError: { code: string; message: string } | null;
  allowedActions: TeamRecoveryAction[];
}

export interface TeamManagement {
  scopeId: string | null;
  region: string | null;
  instanceId: string | null;
  configurationVersion: number;
  mocked: boolean | null;
  inventoryAvailable: boolean;
  enabled: boolean;
  canWrite: boolean;
  canPrepare: boolean;
  items: ManagedTeam[];
  userDirectory: TeamUserDirectory | null;
  operations: TeamOperation[];
}
