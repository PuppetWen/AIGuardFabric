import type { TeamManagement, TeamOperation, TeamPreview, TeamUserDirectory } from '@/types/teamManagement';

export const directoryFixture = (): TeamUserDirectory => ({
  snapshotId: 'directory-one', scopeId: 'scope-one', configurationVersion: 4, mocked: true, instanceId: 'instance-one',
  observedAt: new Date().toISOString(), query: { nameLike: null }, pageComplete: true, complete: false,
  directoryComplete: false, nextCursor: 'opaque-page-two', totalCount: 2, selectionUsable: true, unusableReason: null,
  items: [{ name: 'alice', displayName: 'Alice', status: 'Active', existenceVerified: false, adminEligibility: null }],
});
export const managementFixture = (): TeamManagement => ({
  scopeId: 'scope-one', region: 'cn-hangzhou', instanceId: 'instance-one', configurationVersion: 4,
  mocked: true, enabled: true, inventoryAvailable: true, canPrepare: true, canWrite: true,
  items: [{ teamName: 'existing-team', stateVersion: 3, currentAvailable: true, busy: false, unresolvedDelete: false,
    description: 'Original description', memberNames: ['unloaded-person'], memberNamesAvailable: true,
    adminName: null, leaderName: null, workerNames: [], relationshipAvailable: true }],
  userDirectory: directoryFixture(), operations: [],
});
export const previewFixture = (overrides: Partial<TeamPreview> = {}): TeamPreview => ({
  id: 'preview-one', action: 'update', teamName: 'existing-team', scopeId: 'scope-one', configurationVersion: 4,
  mocked: true, region: 'cn-hangzhou', instanceId: 'instance-one', expectedStateVersion: 3,
  baselineObservedAt: new Date().toISOString(), baselineComplete: true, baselineHash: 'baseline-hash',
  descriptionChanged: true, membersChanged: false,
  before: { description: 'Original description', memberNames: ['unloaded-person'], memberNamesAvailable: true,
    adminName: null, leaderName: null, workerNames: [], workerNamesAvailable: true },
  desired: { description: 'Updated description' }, addedMembers: [], removedMembers: [], verifiedUsers: [],
  expiresAt: new Date(Date.now() + 300_000).toISOString(), previewUsable: true, unusableReason: null, ...overrides,
});
export const operationFixture = (overrides: Partial<TeamOperation> = {}): TeamOperation => ({
  id: 'operation-one', requestId: '11111111-1111-4111-8111-111111111111', previewId: 'preview-one', action: 'update',
  teamName: 'existing-team', scopeId: 'scope-one', configurationVersion: 4, mocked: true, status: 'verified',
  recoveryScopeId: 'scope-one', recoveryConfigurationVersion: 4,
  startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), leaseExpiresAt: null, busy: false,
  cloudWrite: { status: 'accepted', receiptId: 'receipt-one', providerRequestId: 'provider-one', providerCode: null, httpStatus: 200 },
  readback: { status: 'matched', observedAt: new Date().toISOString(), resourceState: 'present', matchedFields: ['Description'], conflictFields: [] },
  inventoryPublish: { status: 'published', checkedAt: new Date().toISOString(), errorCode: null },
  safeError: null, allowedActions: ['read_receipt'], ...overrides,
});
