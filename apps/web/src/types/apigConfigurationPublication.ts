export interface ModelBinding { httpApiId: string; gatewayId: string; environmentId: string }
export interface ContentBinding { model: ModelBinding; attachmentId: string; pluginId: string; classId: string; classVersion: string }
export type ConfigurationBinding = { kind: 'content'; binding: ContentBinding } | { kind: 'models'; binding: ModelBinding };
export interface ConfigurationTarget {
  targetScopeId: string; writeResourceId: string; configurationId: string; configurationVersion: number;
  sourceLabel: string; region: string; endpoint: string; binding: ConfigurationBinding;
  mocked: boolean; transportMode: 'mock' | 'live' | 'loopback-test';
}
export interface ContentSettings { enabled: boolean; checkRequest: boolean; checkResponse: boolean; denyCode: number }
export interface ModelService { serviceId: string; version: string | null; modelName: string; weight: number }
export interface ServicePatch extends ModelService { expectedModelName: string }
export interface ConfigurationView { settings?: ContentSettings; responseMayBecomeNonStreaming?: boolean; services?: ModelService[];
  backendScene?: string; selectedDeploymentIndex?: number; basePath?: string; deploymentVerified?: null; consumerApplied?: null }
export interface ConfigurationObservation {
  id: string; requestId: string; target: ConfigurationTarget; startedAt: string; observedAt: string; fingerprint: string;
  contentHash: string; contentBytes: number; view: ConfigurationView; usable: boolean; reason: string | null;
  deploymentVerified: null; consumerApplied: null;
}
export interface ConfigurationDiff { before: ConfigurationView; after: ConfigurationView; baselineHash: string; desiredHash: string;
  cloudCas: false; deploymentVerified: null; consumerApplied: null }
export interface ConfigurationPreview {
  id: string; requestId: string; target: ConfigurationTarget; stateVersion: number; action: 'publish' | 'rollback';
  sourcePublicationId: string | null; observationId: string; baselineObservedAt: string; baselineFingerprint: string;
  desiredHash: string; desiredBytes: number; diff: ConfigurationDiff; expiresAt: string; previewUsable: boolean;
  consumedBy: string | null; reason: string | null; acknowledgeUnknownOperationId: string | null;
  unknownOverlapWarning: boolean; allowedActions: string[]; noCloudCas: true; deploymentVerified: null; consumerApplied: null;
}
export interface ConfigurationOperation {
  requestId: string; previewId: string; target: ConfigurationTarget; action: 'publish' | 'rollback'; sourcePublicationId: string | null;
  startedAt: string; submittedAt: string; finishedAt: string | null; leaseExpiresAt: string;
  status: 'started' | 'verified' | 'conflict' | 'failed' | 'uncertain' | 'superseded' | 'archived'; originalStatus: string | null;
  archived: boolean; archivedAt: string | null; archivable: boolean; allowedActions: string[];
  cloudWrite: { status: 'not_attempted' | 'attempting' | 'accepted' | 'unknown'; providerRequestId: string | null };
  readback: { status: 'not_attempted' | 'matched' | 'different' | 'unavailable'; observedAt: string | null; currentHash: string | null };
  localPublication: { status: 'not_staged' | 'pending_audit' | 'published' }; completionState: 'complete' | 'pending_audit' | 'running';
  safeReason: string | null; consumerApplied: null; deploymentVerified: null; configurationObserved: boolean;
  supersededBy: string | null; sourceCurrent: boolean | null; recoveryScopeId: string | null; recoveryConfigurationVersion: number | null;
}
export interface ConfigurationHistory { publicationId: string; target: ConfigurationTarget; verifiedAt: string; contentHash: string;
  diff: ConfigurationDiff; rollbackAvailable: boolean; reason: string | null }
export interface ConfigurationState {
  configured: boolean; enabled: boolean | null; binding: ConfigurationTarget | null; bindingReason: string | null;
  stateVersion: number; generation: number; busy: boolean; leaseExpiresAt: string | null; canObserve: boolean;
  canInitializeMockFixture: boolean; canPrepare: boolean; canApply: boolean; unresolvedOperationId: string | null;
  observation: ConfigurationObservation | null; operations: ConfigurationOperation[]; history: ConfigurationHistory[];
  detailedRunCount: number; archivedCount: number; storedContentBytes: number; configurationObserved: boolean;
  deploymentVerified: null; consumerApplied: null; noCloudCas: true;
  limits: { maxDetailedRuns: number; maxPreviews: number; maxObservations: number; maxArchive: number; maxContentBytes: number;
    maxRecordBytes: number; maxStoredContentBytes: number; maxServices: number; maxDriverSeconds: number;
    maxOperationSeconds: number; leaseSeconds: number; previewSeconds: number; observationSeconds: number };
}
export type ConfigurationChange = { action: 'content'; settings: ContentSettings } | { action: 'models'; services: ServicePatch[] }
  | { action: 'rollback'; publication_id: string };
export interface ObserveInput { request_id: string; configuration_version: number; confirm_live: boolean; initialize_mock_fixture?: boolean }
export interface PreviewInput { request_id: string; configuration_version: number; observation_id: string; expected_state_version: number;
  change: ConfigurationChange; acknowledge_unknown_operation_id?: string }
export interface ApplyInput { request_id: string; preview_id: string; expected_state_version: number; confirm_apply: boolean;
  confirm_preserved_private_configuration: boolean; confirm_streaming_or_shared_impact: boolean; confirm_no_cloud_cas: boolean;
  confirm_live: boolean; confirm_unknown_overlap: boolean }
export type ApplyConfirmations = Omit<ApplyInput, 'request_id' | 'preview_id' | 'expected_state_version'>;
