export interface Source {
  configurationId: string; configurationVersion: number; groupId: string;
  region: string; transportMode: 'mock' | 'live' | 'loopback_test'; mocked: boolean;
}
export interface Outcome { delivery: 'not_sent' | 'accepted' | 'rejected' | 'unknown'; providerRequestId: string | null; finishedAt: string }
export interface Attempt {
  id: string; requestId: string; phase: 'admitted' | 'started' | 'complete'; admittedAt: string;
  startedAt: string | null; leaseExpiresAt: string;
  completionState: 'complete' | 'pending_audit' | 'uncertain' | 'in_flight'; outcome: Outcome | null;
  pendingAudit: boolean; mocked: boolean; providerWriteAttempted: boolean | null; consumerApplied: 'unknown';
}
export interface Item {
  id: string; enqueueRequestId: string; name: string; action: 'PutCustomEvent' | 'PutCustomMetric';
  payloadHash: string; payloadBytes: number; queuedAt: string; archivedAt: string | null;
  originalSource: Source; sourceCurrent: boolean; attemptCount: number; lastAttempt: Attempt | null;
  deadLetter: boolean; canSend: boolean; canRecoverLocal: boolean; canArchive: boolean;
}
export interface QueueState {
  generation: number; storedContentBytes: number; permanentFactCount: number;
  page: number; pageSize: number; total: number; items: Item[]; source: Source | null;
  limits: { detailedItems: number; permanentFacts: number; attemptsPerItem: number;
    enqueueBatch: number; sendBatch: number; archiveBatch: number; contentBytes: number };
  automaticRetry: false; exactlyOnce: false; consumerApplied: 'unknown';
}
export type Payload = { kind: 'event'; name: string; content: string; at: string }
  | { kind: 'metric'; name: string; value: number; dimensions: Record<string, string>; at: string };
export interface EnqueueInput { request_id: string; configuration_version: number; expected_generation: number;
  items: Payload[]; initialize_mock_fixture: boolean }
export interface SendInput { request_id: string; expected_generation: number; item_ids: string[]; confirm_live: boolean }
export interface ArchiveInput { request_id: string; expected_generation: number; item_ids: string[] }
export interface Receipt {
  id: string; purpose: 'enqueue' | 'send' | 'archive'; inputHash: string; submittedAt: string;
  generation: number; changedCount: number; itemIds: string[]; attemptIds: string[];
  items: Item[]; originalAttempts: Attempt[]; immutableIntent: true; automaticRetry: false;
}
