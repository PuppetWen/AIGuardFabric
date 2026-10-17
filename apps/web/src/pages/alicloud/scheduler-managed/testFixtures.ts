import type { ManagedState, Operation, Preview } from './types';
import type { ObservationReceipt, SchedulerState } from '../scheduler-native/types';
import { job as nativeJob, receipt as nativeReceipt, state as nativeState, target as nativeTarget } from '../scheduler-native/testFixtures';
export { result, deferred } from '../scheduler-native/testFixtures';
export const target = { ...nativeTarget, fingerprint: 'a'.repeat(64) };
export const observationId = '10000000-0000-4000-8000-000000000001';
export const previewId = '50000000-0000-4000-8000-000000000001';
export const operationId = '60000000-0000-4000-8000-000000000001';
export const selectedJob = () => nativeJob('9223372036854775807', { enabled: false, status: 0 });
export function observation(overrides: Partial<ObservationReceipt> = {}): ObservationReceipt {
  const base = nativeReceipt(), jobs = [selectedJob()];
  return { ...base, originalTarget: target, fingerprint: 'b'.repeat(64),
    observation: { ...base.observation!, jobs, fingerprint: 'b'.repeat(64) }, ...overrides };
}
export function native(overrides: Partial<SchedulerState> = {}): SchedulerState {
  return nativeState({ sourceTarget: target, latestObservation: observation(), ...overrides });
}
export function preview(overrides: Partial<Preview> = {}): Preview {
  return { id: previewId, actorId: 'administrator', target, configurationVersion: 1, createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 120_000).toISOString(), fingerprint: 'c'.repeat(64), operationId: null,
    archived: false, canApply: true, archivable: false, before: null, desired: selectedJob(),
    baselineFingerprint: 'b'.repeat(64), cloudCasAvailable: false, callbackBindingEnforced: false, callbackConfigured: null,
    deploymentVerified: null, ...overrides };
}
export function operation(overrides: Partial<Operation> = {}): Operation {
  const at = new Date().toISOString();
  return { requestId: operationId, actorId: 'administrator', claimId: '70000000-0000-4000-8000-000000000001', inputHash: 'd'.repeat(64),
    target, configurationVersion: 1, previewId, action: 'create_disabled', kind: 'report', runtimeName: 'report-generate',
    jobId: selectedJob().id, startedAt: at, submittedAt: at, expiresAt: new Date(Date.now() + 120_000).toISOString(), finishedAt: at,
    status: 'accepted', completionState: 'complete', originalWrite: { attempted: true, status: 'accepted',
      providerRequestId: 'mock-one-action', authorityCurrent: true, originalDeadlineCurrent: true },
    readback: 'matched', readbackAt: at, readbackFingerprint: 'b'.repeat(64), sourceCurrent: true, currentConfigurationVersion: 1,
    archived: false, archivedAt: null, archivable: true, allowedActions: ['read_receipt', 'observe'], preview: null,
    consumerApplied: null, callbackConfigured: null, callbackBindingEnforced: false, deploymentVerified: null, cloudCasAvailable: false, ...overrides };
}
export function state(overrides: Partial<ManagedState> = {}): ManagedState {
  return { target, sourceState: 'available', canManage: true, canPrepare: true, stateVersion: 1, generation: 4,
    archivedCount: 0, storedContentBytes: 1200, activeRequestId: null, latestObservationId: observationId, bindingVersion: 3,
    definitions: [], unknownScopes: [], previews: [], operations: [], consistency: 'statement', previewTotal: 0, operationTotal: 0,
    previewsTruncated: false, operationsTruncated: false, limits: { maxPreviews: 128, maxOperations: 128,
      maxStoredBytes: 67_108_864, maxDetailBytes: 262_144, maxArchive: 48, pageSize: 50, maxMockJobs: 128, previewSeconds: 120 },
    cloudCasAvailable: false, callbackBindingEnforced: false, callbackConfigured: null, deploymentVerified: null, ...overrides };
}
