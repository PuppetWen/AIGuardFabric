import type { CloudConfig } from '@/api/cloud';
import type { ApiResult } from '@/api/dataSource';
import type { Policy } from '@/types/domain';
import type { Observation, Operation, Preview, PublicationState, Target } from './types';
export const target: Target = {
  targetScopeId: '10000000-0000-4000-8000-000000000001', configurationId: '10000000-0000-4000-8000-000000000002', configurationVersion: 1,
  sourceLabel: 'configured-source-summary', region: 'explicit-region', instanceId: 'explicit-instance', engineOrigin: 'https://nacos.example.test',
  namespaceId: '', group: 'AGF', dataId: 'owned-policy.json', dialect: 'nacos-http-v2-cas', mocked: true, transportMode: 'mock',
};
export const policyId = '20000000-0000-4000-8000-000000000001';
export const operationId = '30000000-0000-4000-8000-000000000001';
export function observation(patch: Partial<Observation> = {}): Observation {
  const at = new Date().toISOString();
  return { id: '40000000-0000-4000-8000-000000000001', requestId: '40000000-0000-4000-8000-000000000002', target,
    startedAt: at, observedAt: at, contentMd5: 'observed-md5', contentHash: 'observed-sha256', contentBytes: 0,
    contentEmpty: true, usable: true, reason: null, ...patch };
}
export function state(patch: Partial<PublicationState> = {}): PublicationState {
  return { configured: true, enabled: true, binding: target, stateVersion: 2, generation: 4, canObserve: true, canPrepare: true, canApply: true,
    bindingReason: null, busy: false, leaseExpiresAt: null, unresolvedOperationId: null, observation: observation(), operations: [], history: [],
    detailedRunCount: 0, archivedCount: 0, storedContentBytes: 0, consumerApplied: null,
    limits: { maxPolicies: 20, maxContentBytes: 262144, maxRecordBytes: 1048576, maxMainBytes: 4194304, maxAggregateAgentIds: 500,
      maxStoredContentBytes: 67108864, maxDetailedRuns: 128, maxPreviews: 32, maxObservations: 8, maxArchive: 100,
      maxDriverSeconds: 30, maxOperationSeconds: 110, leaseSeconds: 120, previewSeconds: 120, observationSeconds: 300 }, ...patch };
}
export function preview(patch: Partial<Preview> = {}): Preview {
  return { id: '50000000-0000-4000-8000-000000000001', requestId: '50000000-0000-4000-8000-000000000002', target, stateVersion: 2,
    action: 'publish', sourcePublicationId: null, observationId: observation().id, baselineObservedAt: new Date().toISOString(), baselineMd5: 'observed-md5',
    baselineHash: 'observed-sha256', baselineBytes: 0, desiredHash: 'trusted-bundle-sha256', desiredBytes: 1200,
    sourcePolicyVersions: [{ policyId, version: 4 }], currentPolicyVersions: [{ policyId, version: 4 }],
    expiresAt: new Date(Date.now() + 120000).toISOString(), previewUsable: true, reason: null, consumedBy: null,
    casSemantics: 'content-md5-upsert', consumerApplied: null, acknowledgeUnknownOperationId: null, unknownOverlapWarning: false, allowedActions: ['apply'], ...patch };
}
export function operation(patch: Partial<Operation> = {}): Operation {
  const at = new Date().toISOString();
  return { requestId: operationId, previewId: preview().id, target, action: 'publish', sourcePublicationId: null,
    startedAt: at, submittedAt: at, finishedAt: at, leaseExpiresAt: new Date(Date.now() + 120000).toISOString(),
    status: 'verified', originalStatus: null, archived: false, archivedAt: null, archivable: true,
    cloudWrite: { status: 'accepted' }, readback: { status: 'matched', observedAt: at, currentHash: 'trusted-bundle-sha256' },
    localPublication: { status: 'published' }, completionState: 'complete', safeReason: null, consumerApplied: null,
    supersededBy: null, sourceCurrent: true, currentPolicyVersions: [{ policyId, version: 4 }],
    recoveryScopeId: target.targetScopeId, recoveryConfigurationVersion: 1, allowedActions: ['read_receipt', 'observe', 'archive'], ...patch };
}
export function policy(): Policy {
  return { id: policyId, version: 4, name: 'Actual signed policy', description: 'Owned test policy', action: 'deny', priority: 1,
    lifecycle: 'enforced', interceptPoints: [], expression: '', code: 'true ? {"action":"deny"} : {}', codeLanguage: 'cel',
    enabled: true, dryRun: false, hitCount24h: 0, blockedCount24h: 0,
    signature: { status: 'signed', signer: 'test', keyId: 'test', digest: 'digest', signedAt: new Date().toISOString() },
    updatedAt: new Date().toISOString(), author: 'test' };
}
export function config(version = 1): CloudConfig {
  return { name: 'alicloud-mse', displayName: 'MSE', enabled: true, mock: true, environmentMock: true, version,
    endpoint: 'https://mse-openapi.example.test', secretKeys: ['access_key_id'], operations: [],
    settings: { endpoint: 'https://preserved-openapi.example.test', account_id: 'existing-source-label', credential_source: 'ecs-role',
      engine_origin: target.engineOrigin, region_id: target.region, instance_id: target.instanceId,
      config_group: target.group, config_data_id: target.dataId, config_dialect: target.dialect, managed_upsert_confirmed: true } };
}
export function result<T>(data: T): ApiResult<T> { return { data, meta: { source: 'live', elapsedMs: 1, at: Date.now() } }; }
export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(yes => { resolve = yes; }); return { promise, resolve };
}
