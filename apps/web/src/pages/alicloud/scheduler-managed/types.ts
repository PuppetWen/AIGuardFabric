import type { SourceTarget, SchedulerJob, SchedulerKind } from '../scheduler-native/types';
export type { SourceTarget, SchedulerJob };
export type JobKind = SchedulerKind;
export type Action = 'create_disabled' | 'update_schedule' | 'disable' | 'enable';
export interface SchedulePatch { time_type?: number; time_expression?: string; calendar?: string; timezone?: string;
  max_attempt?: number; attempt_interval?: number }
export type Change = { action: 'create_disabled'; declaration: { kind: JobKind; name: string; schedule: SchedulePatch; total: 1 } }
  | { action: 'update_schedule'; patch: SchedulePatch } | { action: 'disable' | 'enable' };
export interface PreviewInput { request_id: string; configuration_version: number; expected_binding_version: number;
  observation_id: string; change: Change; selection?: { kind: JobKind; app_id: string; job_id: string; observation_fingerprint: string } }
export interface ApplyInput { preview_id: string; preview_fingerprint: string; confirm_no_cloud_cas: true;
  confirm_callback_unknown: true; confirm_live: boolean; confirm_unknown_overlap: boolean }
export interface Preview { id: string; actorId: string; target: SourceTarget; configurationVersion: number; createdAt: string;
  expiresAt?: string; fingerprint: string; operationId: string | null; archived: boolean; canApply: boolean; archivable: boolean;
  before?: SchedulerJob | null; desired?: SchedulerJob; baselineFingerprint?: string; archivedAt?: string;
  cloudCasAvailable: false; callbackBindingEnforced: false; callbackConfigured: null; deploymentVerified: null }
export interface WriteEvidence { attempted: boolean; status: 'accepted' | 'rejected' | 'unknown'; providerRequestId: string | null;
  authorityCurrent: boolean; originalDeadlineCurrent: boolean }
export interface Operation { requestId: string; actorId: string; claimId: string; inputHash: string; target: SourceTarget;
  configurationVersion: number; previewId: string; action: Action; kind: JobKind; runtimeName: string; jobId: string | null;
  startedAt: string; submittedAt: string; expiresAt: string; finishedAt: string | null; status: 'started' | 'accepted' | 'rejected' | 'uncertain' | 'archived';
  completionState: 'running' | 'pending_audit' | 'complete'; originalWrite: WriteEvidence | null; readback: 'matched' | 'different' | 'unknown';
  readbackAt: string | null; readbackFingerprint: string | null; sourceCurrent: boolean | null; currentConfigurationVersion: number | null;
  archived: boolean; archivedAt: string | null; archivable: boolean; allowedActions: ('read_receipt' | 'recover_local' | 'observe')[];
  preview: { before: SchedulerJob | null; desired: SchedulerJob; fingerprint: string; baselineFingerprint: string } | null;
  consumerApplied: null; callbackConfigured: null; callbackBindingEnforced: false; deploymentVerified: null; cloudCasAvailable: false }
export interface ManagedState { target: SourceTarget | null; sourceState: 'available' | 'disabled_or_missing' | 'unavailable';
  canManage: boolean; canPrepare: boolean; stateVersion: number; generation: number; archivedCount: number; storedContentBytes: number;
  activeRequestId: string | null; latestObservationId: string | null; bindingVersion: number;
  definitions: { scopeId: string; kind: JobKind; jobId: string; requestId: string; total: 1 }[];
  unknownScopes: { requestId: string; scopeId: string; expiresAt: string; resource: { tenant: string; clusterId: string; appName: string } }[]; previews: Preview[]; operations: Operation[];
  consistency: 'statement'; previewTotal: number; operationTotal: number; previewsTruncated: boolean; operationsTruncated: boolean;
  limits: { maxPreviews: number; maxOperations: number; maxStoredBytes: number; maxDetailBytes: number; maxArchive: number;
    pageSize: 50; maxMockJobs: number; previewSeconds: 120 }; cloudCasAvailable: false; callbackBindingEnforced: false;
  callbackConfigured: null; deploymentVerified: null }
export interface ArchiveResult { generation: number; archivedCount: number; storedContentBytes: number; stateVersion: number }
export type Intent = { purpose: 'preview'; id: string; body: PreviewInput; state: 'waiting' | 'unknown' | 'rejected' | 'known' }
  | { purpose: 'apply'; id: string; body: ApplyInput; state: 'waiting' | 'unknown' | 'known' };
