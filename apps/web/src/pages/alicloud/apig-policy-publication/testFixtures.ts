import type { CloudConfig } from '@/api/cloud';
import type { ApiResult } from '@/api/dataSource';
import type { ApigObservation, ApigOperation, ApigPreview, ApigPublicationState, ApigTarget } from '@/types/apigPolicyPublication';

export const policyId = '10000000-0000-4000-8000-000000000001', operationId = '20000000-0000-4000-8000-000000000002';
export const target: ApigTarget = { targetScopeId: '30000000-0000-4000-8000-000000000003', writeResourceId: '30000000-0000-4000-8000-000000000004',
  configurationId: '30000000-0000-4000-8000-000000000005', configurationVersion: 1, sourceLabel: 'Actual configured APIG source', region: 'cn-hangzhou',
  endpoint: 'https://apig.example.test', mocked: true, transportMode: 'mock',
  binding: { httpApiId: 'api-agf-demo', gatewayId: 'gw-agf-demo', environmentId: 'env-agf-demo', policyId: 'policy-agf-demo', attachmentId: 'attachment-agf-demo' } };
export function result<T>(data: T): ApiResult<T> { return { data, meta: { source: 'live', elapsedMs: 1, at: Date.now() } }; }
export function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(accept => { resolve = accept; }); return { resolve, promise }; }
export function observation(overrides: Partial<ApigObservation> = {}): ApigObservation {
  return { id: '40000000-0000-4000-8000-000000000004', requestId: '40000000-0000-4000-8000-000000000004', target,
    startedAt: new Date(Date.now() - 1000).toISOString(), observedAt: new Date().toISOString(), fingerprint: 'actual-fingerprint', configHash: 'actual-config-hash',
    contentHash: 'actual-evidence-hash', contentBytes: 1234, usable: true, reason: null,
    slots: [{ managedLimit: 'RequestPerMinute', currentLimit: 100, supported: true, reason: null }], ...overrides };
}
export function preview(overrides: Partial<ApigPreview> = {}): ApigPreview {
  return { id: '50000000-0000-4000-8000-000000000005', requestId: '50000000-0000-4000-8000-000000000005', target, stateVersion: 2,
    action: 'publish', sourcePublicationId: null, observationId: observation().id, baselineObservedAt: observation().observedAt,
    baselineFingerprint: 'actual-fingerprint', baselineConfigHash: 'actual-config-hash', managedLimit: 'RequestPerMinute', previousLimit: 100, desiredLimit: 40,
    desiredHash: 'desired-config-hash', desiredBytes: 220, sourcePolicyVersions: [{ policyId, version: 4 }], currentPolicyVersions: [{ policyId, version: 4 }],
    expiresAt: new Date(Date.now() + 120000).toISOString(), previewUsable: true, reason: null, consumedBy: null, casSemantics: 'none', noCloudCas: true,
    sharedPolicyImpact: null, consumerApplied: null, acknowledgeUnknownOperationId: null, unknownOverlapWarning: false, allowedActions: ['apply', 'read_receipt'], ...overrides };
}
export function operation(overrides: Partial<ApigOperation> = {}): ApigOperation {
  return { requestId: operationId, previewId: preview().id, target, action: 'publish', sourcePublicationId: null,
    startedAt: new Date().toISOString(), submittedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), leaseExpiresAt: new Date(Date.now() + 120000).toISOString(),
    status: 'verified', originalStatus: null, archived: false, archivedAt: null, archivable: true,
    cloudWrite: { status: 'accepted', providerRequestId: 'actual-provider-ack' }, readback: { status: 'matched', observedAt: new Date().toISOString(), currentHash: 'desired-config-hash' },
    localPublication: { status: 'published' }, completionState: 'complete', safeReason: null, consumerApplied: null, supersededBy: null, sourceCurrent: true,
    sourcePolicyVersions: [{ policyId, version: 4 }], currentPolicyVersions: [{ policyId, version: 4 }], recoveryScopeId: target.targetScopeId,
    recoveryConfigurationVersion: 1, allowedActions: ['read_receipt', 'observe', 'archive'], ...overrides };
}
export function state(overrides: Partial<ApigPublicationState> = {}): ApigPublicationState {
  return { configured: true, enabled: true, binding: target, stateVersion: 2, generation: 3, canInitializeMockFixture: true,
    canObserve: true, canPrepare: true, canApply: true, bindingReason: null, busy: false, leaseExpiresAt: null, unresolvedOperationId: null, observation: observation(),
    sources: { items: [{ policyId, version: 4, name: 'Actual projectable policy', eligible: true, reason: null,
      source: { policyId, policyVersion: 4, quotaId: '60000000-0000-4000-8000-000000000006', quotaVersion: 3, quotaFingerprint: 'actual-quota-fingerprint', managedLimit: 'RequestPerMinute', limit: 40 } }],
    page: 1, pageSize: 20, total: 1, policyCount: 1, eligibleCount: 1, totalPages: 1, truncated: false, reason: null },
    operations: [], history: [], detailedRunCount: 0, archivedCount: 0, storedContentBytes: 0, consumerApplied: null, sharedPolicyImpact: null, noCloudCas: true,
    limits: { maxPolicies: 1, maxContentBytes: 655360, maxProviderConfigBytes: 65536, maxRecordBytes: 1048576, maxMainBytes: 4194304, maxAggregateAgentIds: 500,
      maxStoredContentBytes: 67108864, maxDetailedRuns: 128, maxPreviews: 32, maxObservations: 8, maxArchive: 100, maxDriverSeconds: 30,
      maxOperationSeconds: 110, leaseSeconds: 120, previewSeconds: 120, observationSeconds: 300 }, ...overrides };
}
export function config(version = 1): CloudConfig {
  return { name: 'alicloud-apig', displayName: 'APIG', enabled: true, mock: true, environmentMock: false, version, endpoint: 'https://apig.example.test',
    settings: { region_id: 'cn-hangzhou', policy_http_api_id: 'api-agf-demo', policy_gateway_id: 'gw-agf-demo', policy_environment_id: 'env-agf-demo',
      policy_id: 'policy-agf-demo', policy_attachment_id: 'attachment-agf-demo', policy_dialect: 'apig-2024-03-27-ai-token-rate-limit',
      managed_policy_confirmed: true, account_id: 'actual-account-label', custom_preserved: 'user-owned-value' }, secretKeys: ['access_key_id'], operations: [] };
}
