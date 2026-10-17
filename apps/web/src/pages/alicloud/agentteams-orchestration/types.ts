export interface DeclaredNode { node_id: string; name: string; agent_ids: string[]; depends_on: string[]; trigger: 'manual' | 'event' | 'cron'; cron?: string | null }
export interface Definition { schema_version: 1; tenant_id: string; cloud_team_id: string; inventory_fingerprint: string; nodes: DeclaredNode[] }
export type Direction = 'pull' | 'push' | 'both';
export interface Source { configurationVersion: number; region: string; instanceId: string; inventoryFingerprint: string; mocked: true; source: 'application_owned' }
export interface RecordView { teamName: string; version: number; source: Source; local: Definition | null; receiver: Definition | null; receiverAvailable: boolean;
  updatedAt: string; vendorDagAvailable: false; consumerApplied: null; providerCalled: false }
export interface Target { teamName: string; source: Source; workers: { name: string; assetId: string }[]; template: Definition; current: RecordView | null; sourceCurrent: boolean | null }
export interface State { modeSupported: boolean; canManage: boolean; durable: boolean; generation: number; intentCount: number; teams: Target[]; records: RecordView[]; consumerApplied: null;
  limits: { maxTeams: number; maxIntents: number; maxBytes: number; maxNodes: number; maxDocumentBytes: number } }
export type Change = { action: 'save_definition'; definition: Definition } | { action: 'sync'; direction: Direction };
export interface Input { request_id: string; expected_version: number; configuration_version: number; inventory_fingerprint: string; change: Change;
  confirm_application_owned: boolean; confirm_mock_sync: boolean; confirm_source_change: boolean }
export interface Difference { added: string[]; removed: string[]; changed: string[] }
export interface Preview { teamName: string; requestId: string; expectedVersion: number; configurationVersion: number; difference: Difference; result: RecordView;
  providerCalled: false; consumerApplied: null; previewOnly: true }
export interface Receipt { requestId: string; teamName: string; bodyHash: string; version: number; source: Source; action: Change['action']; direction: Direction | null;
  status: 'committed'; localHash: string | null; receiverHash: string | null; localNodeCount: number | null; receiverNodeCount: number | null;
  difference: Difference; committedAt: string; durable: boolean; immutable: true; providerCalled: false; consumerApplied: null }
export interface Draft { target: Target; expectedVersion: number; text: string; action: Change['action']; direction: Direction; confirmed: boolean; mockConfirmed: boolean; sourceConfirmed: boolean }
export interface Prepared { team: string; body: Readonly<Input>; preview: Preview }
export interface Pending extends Prepared { phase: 'in_flight' | 'unknown' | 'committed' | 'rejected' }
