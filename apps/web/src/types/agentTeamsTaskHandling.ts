/** Local operator annotations on received error observations, never remote execution proof. */
export type HandlingDecision = 'acknowledged' | 'external_action_reported' | 'resolved_by_operator';
export interface HandlingWindow { from: string; until: string }
export interface HandlingEvent {
  id: string; category: 'collector_reported_error'; originalStatus: 'error'; externalEventId: string;
  sourceId: string; scopeId: string; bindingId: string; eventTime: string; receivedAt: string;
  taskId: string | null; traceId: string | null; mocked: boolean; evidenceIdentityHash: string;
  messagePreview?: string; fromTeam?: string | null; fromWorker?: string | null;
  handling: null | { version: number; decision: HandlingDecision; updatedAt: string;
    subjectId: string; subjectKind: string; archived: boolean; archivedAt: string | null;
    revisionCount: number; history: { requestId: string; version: number; decision: HandlingDecision; updatedAt: string }[] };
  currentSource: { sourceExists: boolean; sourceGone: boolean; sourceEnabled: boolean | null;
    sourceName: string | null; cloudConfigurationVersion: number | null; cloudEnabled: boolean | null;
    fingerprint: string | null; annotationAllowedWhenDisabled: boolean; businessReplay: false };
  allowedActions: string[]; cloudExecutionConfirmed: false; businessReplayImplemented: false;
}
export interface HandlingPage {
  items: HandlingEvent[]; total: number; nextCursor: string | null; truncated: boolean;
  windowFrom: string; windowTo: string; asOfReceivedAt: string; evidenceLimit: number;
  consistency: 'statement'; complete: false; category: 'collector_reported_error'; generation: number;
  activeHandledCount: number; archivedCount: number; businessReplayImplemented: false;
}
export interface ResolutionInput {
  request_id: string; expected_version: number; expected_cloud_configuration_version: number;
  expected_source_fingerprint: string; decision: HandlingDecision;
}
export interface ArchiveInput {
  request_id: string; expected_generation: number; event_ids: string[];
  sources: { source_id: string; fingerprint: string | null }[];
  expected_cloud_configuration_version: number | null;
}
export interface HandlingReceipt {
  purpose: 'operator-resolution' | 'operator-archive'; requestId: string; eventId?: string;
  version?: number; decision?: HandlingDecision; generation?: number; eventIds?: string[];
  changedCount?: number; cloudExecutionConfirmed: false; businessReplay: false;
}
