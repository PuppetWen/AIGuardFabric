export interface WorkerQuotaRule {
  id: string;
  name: string;
  version: number;
  targetId: string | null;
  scope: 'tenant' | 'agent' | 'session';
  dimension: 'tokens' | 'requests' | 'concurrency' | 'cost';
  window: 'minute' | 'hour' | 'day' | 'month' | 'session' | 'total';
  limit: number;
  enabled: boolean;
  onExceed: string;
}

export interface WorkerQuotaObservation {
  id: string;
  observedAt: string;
  quotaVersion: number;
  cloudVersion: number;
  bindingVersion: number;
  mocked: boolean;
  previewUsable: boolean;
  usageLimit: number;
  limitType: string;
  periodType: string;
  ruleStatus: string | null;
  usedAmount: number | null;
  overLimit: boolean | null;
}

export interface WorkerQuotaOperation {
  id: string;
  requestId: string;
  status: 'started' | 'verified' | 'failed' | 'uncertain' | 'superseded';
  startedAt: string;
  finishedAt: string | null;
  mocked: boolean;
  changed: boolean;
  error: string | null;
}

export interface WorkerQuotaBinding {
  assetId: string;
  workerName: string;
  version: number;
  quotaId: string;
  quotaVersion: number | null;
  quotaName: string | null;
  platformLimit: number | null;
  cloudVersion: number;
  scopeId: string;
  mocked: boolean;
  enabled: boolean;
  state: 'unverified' | 'in-sync' | 'drift' | 'stale' | 'disabled';
  busy: boolean;
  canObserve: boolean;
  leaseExpiresAt: string | null;
  driftAlertId?: string | null;
  observation: WorkerQuotaObservation | null;
  lastOperation: WorkerQuotaOperation | null;
  boundAt: string;
}

export interface WorkerQuotas {
  inventoryAvailable: boolean;
  cloudVersion: number;
  mocked: boolean | null;
  canWrite: boolean;
  workers: { assetId: string; name: string }[];
  quotas: WorkerQuotaRule[];
  items: WorkerQuotaBinding[];
}

export interface WorkerQuotaBindRequest {
  expected_version: number;
  quota_id: string;
  quota_version: number;
  enabled: boolean;
}

export interface WorkerQuotaObserveRequest {
  request_id: string;
  expected_binding_version: number;
  expected_quota_version: number;
  configuration_version: number;
  confirm_live: boolean;
}

export interface WorkerQuotaSyncRequest extends WorkerQuotaObserveRequest {
  preview_id: string;
}

export interface WorkerQuotaObserveResult {
  binding: WorkerQuotaBinding;
  observation: WorkerQuotaObservation;
}

export interface WorkerQuotaSyncResult {
  binding: WorkerQuotaBinding;
  operation: WorkerQuotaOperation;
}
