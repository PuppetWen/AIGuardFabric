import type { CloudConfig } from '@/api/cloud';
import type { ApiResult } from '@/api/dataSource';
import type { ConfigurationObservation, ConfigurationOperation, ConfigurationPreview, ConfigurationState, ConfigurationTarget } from '@/types/apigConfigurationPublication';
export const operationId = '20000000-0000-4000-8000-000000000002', historicalId = '20000000-0000-4000-8000-000000000099';
export const target: ConfigurationTarget = { targetScopeId: '30000000-0000-4000-8000-000000000003', writeResourceId: '30000000-0000-4000-8000-000000000004',
  configurationId: '30000000-0000-4000-8000-000000000005', configurationVersion: 1, sourceLabel: 'Actual configured APIG source', region: 'cn-hangzhou',
  endpoint: 'https://apig.example.test', mocked: true, transportMode: 'mock', binding: { kind: 'content', binding: {
    model: { httpApiId: 'api-owned', gatewayId: 'gw-owned', environmentId: 'env-owned' }, attachmentId: 'pa-owned', pluginId: 'pl-owned', classId: 'cls-owned', classVersion: '1.0.0' } } };
export function result<T>(data: T): ApiResult<T> { return { data, meta: { source: 'live', elapsedMs: 1, at: Date.now() } }; }
export function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(accept => { resolve = accept; }); return { resolve, promise }; }
export function observation(overrides: Partial<ConfigurationObservation> = {}): ConfigurationObservation {
  return { id: '40000000-0000-4000-8000-000000000004', requestId: '40000000-0000-4000-8000-000000000004', target,
    startedAt: new Date(Date.now() - 1000).toISOString(), observedAt: new Date().toISOString(), fingerprint: 'actual-fingerprint', contentHash: 'actual-content-hash',
    contentBytes: 1234, view: { settings: { enabled: true, checkRequest: true, checkResponse: false, denyCode: 403 }, responseMayBecomeNonStreaming: false },
    usable: true, reason: null, deploymentVerified: null, consumerApplied: null, ...overrides };
}
export function preview(overrides: Partial<ConfigurationPreview> = {}): ConfigurationPreview {
  return { id: '50000000-0000-4000-8000-000000000005', requestId: '50000000-0000-4000-8000-000000000005', target, stateVersion: 2,
    action: 'publish', sourcePublicationId: null, observationId: observation().id, baselineObservedAt: observation().observedAt,
    baselineFingerprint: 'actual-fingerprint', desiredHash: 'desired-config-hash', desiredBytes: 220,
    diff: { before: observation().view, after: { settings: { enabled: true, checkRequest: true, checkResponse: true, denyCode: 403 } },
      baselineHash: 'actual-content-hash', desiredHash: 'desired-config-hash', cloudCas: false, deploymentVerified: null, consumerApplied: null },
    expiresAt: new Date(Date.now() + 120000).toISOString(), previewUsable: true, reason: null, consumedBy: null, noCloudCas: true,
    deploymentVerified: null, consumerApplied: null, acknowledgeUnknownOperationId: null, unknownOverlapWarning: false, allowedActions: ['apply', 'read_receipt'], ...overrides };
}
export function operation(overrides: Partial<ConfigurationOperation> = {}): ConfigurationOperation {
  return { requestId: operationId, previewId: preview().id, target, action: 'publish', sourcePublicationId: null,
    startedAt: new Date().toISOString(), submittedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), leaseExpiresAt: new Date(Date.now() + 120000).toISOString(),
    status: 'verified', originalStatus: null, archived: false, archivedAt: null, archivable: true,
    cloudWrite: { status: 'accepted', providerRequestId: 'actual-provider-ack' }, readback: { status: 'matched', observedAt: new Date().toISOString(), currentHash: 'desired-config-hash' },
    localPublication: { status: 'published' }, completionState: 'complete', safeReason: null, consumerApplied: null, deploymentVerified: null,
    configurationObserved: true, supersededBy: null, sourceCurrent: true, recoveryScopeId: target.targetScopeId,
    recoveryConfigurationVersion: 1, allowedActions: ['read_receipt', 'observe', 'archive'], ...overrides };
}
export function state(overrides: Partial<ConfigurationState> = {}): ConfigurationState {
  return { configured: true, enabled: true, binding: target, stateVersion: 2, generation: 3, canInitializeMockFixture: true,
    canObserve: true, canPrepare: true, canApply: true, bindingReason: null, busy: false, leaseExpiresAt: null, unresolvedOperationId: null, observation: observation(),
    operations: [], history: [], detailedRunCount: 0, archivedCount: 0, storedContentBytes: 0, consumerApplied: null, deploymentVerified: null, configurationObserved: false, noCloudCas: true,
    limits: { maxContentBytes: 655360, maxRecordBytes: 1048576, maxStoredContentBytes: 67108864, maxServices: 32,
      maxDetailedRuns: 128, maxPreviews: 32, maxObservations: 8, maxArchive: 100, maxDriverSeconds: 30,
      maxOperationSeconds: 110, leaseSeconds: 120, previewSeconds: 120, observationSeconds: 300 }, ...overrides };
}
export function config(version = 1): CloudConfig {
  return { name: 'alicloud-apig', displayName: 'APIG', enabled: true, mock: true, environmentMock: false, version, endpoint: 'https://apig.example.test',
    settings: { region_id: 'cn-hangzhou', configuration_kind: 'content', configuration_http_api_id: 'api-owned', configuration_gateway_id: 'gw-owned',
      configuration_environment_id: 'env-owned', configuration_attachment_id: 'pa-owned', configuration_plugin_id: 'pl-owned',
      configuration_class_id: 'cls-owned', configuration_class_version: '1.0.0', managed_configuration_confirmed: true,
      account_id: 'actual-account-label', custom_preserved: 'user-owned-value' }, secretKeys: ['access_key_id'], operations: [] };
}
