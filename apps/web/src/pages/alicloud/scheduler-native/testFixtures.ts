import type { ApiResult } from '@/api/dataSource';
import type { Binding, BoundJob, ObservationReceipt, SchedulerJob, SchedulerState, SourceTarget } from './types';

export const observationId = '10000000-0000-4000-8000-000000000001';
export const target: SourceTarget = { tenant: 'tenant-one', configurationId: '20000000-0000-4000-8000-000000000001',
  configurationVersion: 1, scopeId: '30000000-0000-4000-8000-000000000001', fingerprint: 'configured-source-fingerprint',
  region: 'cn-hangzhou', rpcOrigin: 'https://scheduler.example.test/', configuredAccountId: null, accountIdentityVerified: false,
  clusterId: 'actual-configured-cluster', appName: 'actual-configured-application', mocked: true, transportMode: 'mock' };
export function result<T>(data: T): ApiResult<T> { return { data, meta: { source: 'live', elapsedMs: 1, at: Date.now() } }; }
export function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(accept => { resolve = accept; }); return { resolve, promise }; }
export function boundJob(overrides: Partial<BoundJob> = {}): BoundJob {
  const at = new Date().toISOString();
  return { kind: 'report', runtimeName: 'report-generate', jobId: '9007199254741002', eligibility: 'eligible', reason: null,
    decisionObservationId: observationId, decisionAt: at,
    adoptedProof: { proofId: '60000000-0000-4000-8000-000000000001', adoptionVersion: 3, sourceTarget: target,
      observationId, observedAt: at, appId: '9007199254740993', jobId: '9007199254741002', kind: 'report', httpJob: true, enabled: true },
    currentEvidence: { observationId, observedAt: at, sourceTarget: target, appId: '9007199254740993', jobPresent: true,
      jobKind: 'http', httpJob: true, enabled: true }, ...overrides };
}
export function binding(overrides: Partial<Binding> = {}): Binding {
  const version = overrides.version ?? 3, adoptionVersion = overrides.adoptionVersion ?? version, item = boundJob();
  if (adoptionVersion > 0) item.adoptedProof!.adoptionVersion = adoptionVersion;
  else {
    item.eligibility = 'unverified'; item.reason = 'proof_unavailable'; item.adoptedProof = null;
    item.currentEvidence = null; item.decisionObservationId = null; item.decisionAt = null;
  }
  return { version, adoptionVersion, locallyEnabled: true, status: 'partial', current: true, evidenceFresh: true, observationId,
    eligibility: adoptionVersion > 0 ? 'eligible' : 'unverified', qualificationVerified: adoptionVersion > 0, sourceCurrent: true,
    appId: '9007199254740993', verifiedAt: new Date().toISOString(), sourceTarget: target,
    items: [item],
    callbackBindingEnforced: false, deploymentVerified: null, callbackConfigured: null, ...overrides };
}
export function job(id = '9007199254741002', overrides: Partial<SchedulerJob> = {}): SchedulerJob {
  return { id, appName: target.appName, appId: '9007199254740993', name: `Actual job ${id}`, kind: 'http', httpJob: true,
    status: 1, enabled: true, schedule: { kind: 1, expression: '0 0/5 * * * ?', calendar: null, zone: null, utc: null },
    maxAttempt: null, attemptInterval: null, routeStrategy: null, shardCount: null, updateTimeNative: null,
    http: { verified: false, parameters: 'present', handler: 'missing', attributes: 'null', script: 'empty', fingerprint: 'opaque-carrier-hash' }, ...overrides };
}
export function receipt(overrides: Partial<ObservationReceipt> = {}): ObservationReceipt {
  const at = new Date().toISOString();
  return { requestId: observationId, status: 'observed', originalStatus: 'observed', originalTarget: target,
    applicationScopeId: '40000000-0000-4000-8000-000000000001', claimId: '50000000-0000-4000-8000-000000000001',
    startedAt: at, submittedAt: at, observedAt: at, finishedAt: at, leaseExpiresAt: new Date(Date.now() + 120000).toISOString(),
    archived: false, archivedAt: null, available: true, current: true, archivable: true, reason: null, total: 1, appId: '9007199254740993',
    fingerprint: 'observed-fingerprint', listingComplete: true, strongSnapshot: false, callbackBindingEnforced: false,
    deploymentVerified: null, callbackConfigured: null, authorizationAllowed: null, callbackReachability: null, allowedActions: ['read_receipt', 'archive'],
    observation: { scope: { clusterId: target.clusterId, appName: target.appName }, app: { id: '9007199254740993', name: target.appName, title: null, kind: null },
      pagination: { total: 1, listingComplete: true, strongSnapshot: false, pages: [{ number: 1, size: 100, records: 1, requestId: 'actual-provider-read-id' }] },
      fingerprint: 'observed-fingerprint', jobs: [job()], page: 1, pageSize: 50, total: 1, totalPages: 1 }, ...overrides };
}
export function state(overrides: Partial<SchedulerState> = {}): SchedulerState {
  return { tenantId: target.tenant, configured: true, enabled: true, sourceTarget: target, stateVersion: 4, generation: 7,
    busy: false, leaseExpiresAt: null, canObserve: true, canInitMock: true, canBind: true, latestObservation: receipt(),
    bindings: binding(), recentObservations: [receipt()], detailedObservationCount: 1, archivedCount: 0, storedContentBytes: 2000,
    callbackBindingEnforced: false, deploymentVerified: null, callbackConfigured: null,
    limits: { maxJobs: 2000, maxPages: 20, cloudPageSize: 100, pageSize: 100, maxObservations: 128, maxArchive: 100,
      maxObservationBytes: 2097152, maxEncryptedEnvelopeBytes: 4194304, maxStoredBytes: 67108864, maxSeconds: 110,
      observationFreshSeconds: 300, bindingKinds: ['asset-inventory', 'log-pull', 'redteam-cruise', 'rule-hot-reload', 'report', 'archive'] }, ...overrides };
}
