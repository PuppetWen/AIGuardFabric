export type SchedulerKind = 'asset-inventory' | 'log-pull' | 'redteam-cruise' | 'rule-hot-reload' | 'report' | 'archive';
export interface SourceTarget {
  tenant: string; configurationId: string; configurationVersion: number; scopeId: string; fingerprint: string;
  region: string; rpcOrigin: string; configuredAccountId: string | null; accountIdentityVerified: false;
  clusterId: string; appName: string; mocked: boolean; transportMode: 'mock' | 'live' | 'loopback_test';
}
export type BindingEligibility = 'eligible' | 'revoked' | 'unverified';
export type BindingReason = 'proof_unavailable' | 'app_changed' | 'job_missing' | 'job_disabled' | 'job_not_http'
  | 'job_type_unknown' | 'job_status_unknown';
export interface AdoptedProof {
  proofId: string; adoptionVersion: number; sourceTarget: SourceTarget; observationId: string; observedAt: string;
  appId: string; jobId: string; kind: SchedulerKind; httpJob: true; enabled: true;
}
export interface BindingEvidence {
  observationId: string; observedAt: string; sourceTarget: SourceTarget; appId: string; jobPresent: boolean;
  jobKind: string | null; httpJob: boolean | null; enabled: boolean | null;
}
export interface BoundJob {
  kind: SchedulerKind; runtimeName: string; jobId: string; eligibility: BindingEligibility; reason: BindingReason | null;
  decisionObservationId: string | null; decisionAt: string | null; adoptedProof: AdoptedProof | null;
  currentEvidence: BindingEvidence | null;
}
export interface Binding {
  version: number; adoptionVersion: number; locallyEnabled: boolean;
  status: 'disabled' | 'stale' | 'partial' | 'associated' | 'revoked' | 'unverified'; current: boolean;
  eligibility: BindingEligibility; qualificationVerified: boolean; sourceCurrent: boolean;
  evidenceFresh: boolean; observationId: string | null; appId: string | null; verifiedAt: string | null;
  sourceTarget: SourceTarget | null; items: BoundJob[];
  callbackBindingEnforced: false; deploymentVerified: null; callbackConfigured: null;
}
export interface ObservationSummary {
  requestId: string; status: 'reading' | 'observed' | 'failed' | 'interrupted' | 'archived'; originalStatus: string;
  originalTarget: SourceTarget | null; applicationScopeId: string | null; startedAt: string; finishedAt: string | null;
  leaseExpiresAt: string; claimId: string; submittedAt: string | null; observedAt: string | null;
  callbackConfigured: null; archived: boolean; archivedAt: string | null; available: boolean; current: boolean;
  archivable: boolean; reason: string | null; total: number | null; appId: string | null; fingerprint: string | null;
  listingComplete: boolean; strongSnapshot: false; callbackBindingEnforced: false; deploymentVerified: null;
  authorizationAllowed: null; callbackReachability: null; allowedActions: ('read_receipt' | 'archive')[];
}
type Presence = 'missing' | 'null' | 'empty' | 'present';
export interface SchedulerJob {
  id: string; appName: string; appId: string | null; name: string; kind: string | null; httpJob: boolean;
  status: number | null; enabled: boolean | null;
  schedule: { kind: number | null; expression: string | null; calendar: string | null; zone: string | null; utc: boolean | null };
  maxAttempt: number | null; attemptInterval: number | null; routeStrategy: number | null; shardCount: null;
  updateTimeNative: string | null;
  http: { verified: false; parameters: Presence; handler: Presence; attributes: Presence; script: Presence; fingerprint: string };
}
export interface ObservationReceipt extends ObservationSummary {
  observation: null | {
    scope: { clusterId: string; appName: string };
    app: { id: string; name: string; title: string | null; kind: number | null };
    pagination: { total: number; listingComplete: boolean; strongSnapshot: false;
      pages: { number: number; size: number; records: number; requestId: string }[] };
    fingerprint: string; jobs: SchedulerJob[]; page: number; pageSize: number; total: number; totalPages: number;
  };
}
export interface SchedulerState {
  tenantId: string; configured: boolean; enabled: boolean; sourceTarget: SourceTarget | null; stateVersion: number;
  generation: number; busy: boolean; leaseExpiresAt: string | null; canObserve: boolean; canInitMock: boolean; canBind: boolean;
  latestObservation: ObservationSummary | null; bindings: Binding; recentObservations: ObservationSummary[];
  detailedObservationCount: number; archivedCount: number; storedContentBytes: number; callbackBindingEnforced: false;
  deploymentVerified: null; callbackConfigured: null;
  limits: { maxJobs: number; maxPages: number; cloudPageSize: number; pageSize: number; maxObservations: number;
    maxArchive: number; maxObservationBytes: number; maxEncryptedEnvelopeBytes: number; maxStoredBytes: number;
    maxSeconds: number; observationFreshSeconds: number; bindingKinds: SchedulerKind[] };
}
export interface ObserveInput { request_id: string; configuration_version: number; confirm_live: boolean; initialize_mock_fixture: boolean }
export interface Assignment { kind: SchedulerKind; job_id: string }
export type BindingInput = { action: 'replace'; request_id: string; expected_version: number; configuration_version: number;
  observation_id: string; bindings: Assignment[]; confirm_local_only: true }
  | { action: 'disable'; request_id: string; expected_version: number };
export interface ArchiveInput { expected_generation: number; request_ids: string[] }
export interface ArchiveResult { generation: number; archivedCount: number; storedContentBytes: number; stateVersion: number }
