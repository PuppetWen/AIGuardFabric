import type { ApiResult } from '@/api/dataSource';
import type { Definition, Input, Preview, Receipt, RecordView, State, Target } from './types';
export const tenantId = '10000000-0000-5000-8000-000000000001', requestId = '10000000-0000-5000-8000-000000000002';
export const fingerprint = 'a'.repeat(64);
export function definition(): Definition {
  return { schema_version: 1, tenant_id: tenantId, cloud_team_id: 'Owned Team', inventory_fingerprint: fingerprint,
    nodes: [{ node_id: 'root', name: 'Existing root', agent_ids: ['Actual Worker'], depends_on: [], trigger: 'manual', cron: null }] };
}
export function record(overrides: Partial<RecordView> = {}): RecordView {
  return { teamName: 'Owned Team', version: 3, source: { configurationVersion: 1, region: 'cn-hangzhou', instanceId: 'owned-instance', inventoryFingerprint: fingerprint, mocked: true, source: 'application_owned' },
    local: definition(), receiver: null, receiverAvailable: false, updatedAt: '2026-10-02T10:00:00Z', vendorDagAvailable: false, consumerApplied: null, providerCalled: false, ...overrides };
}
export function target(overrides: Partial<Target> = {}): Target {
  const source = overrides.source ?? record().source;
  return { teamName: 'Owned Team', source, workers: [{ name: 'Actual Worker', assetId: '10000000-0000-5000-8000-000000000003' }],
    template: { ...definition(), inventory_fingerprint: source.inventoryFingerprint, nodes: [] }, current: record(), sourceCurrent: true, ...overrides };
}
export function state(overrides: Partial<State> = {}): State {
  return { modeSupported: true, canManage: true, durable: false, generation: 3, intentCount: 3, teams: [target()], records: [record()], consumerApplied: null,
    limits: { maxTeams: 64, maxIntents: 512, maxBytes: 3 * 1024 * 1024, maxNodes: 128, maxDocumentBytes: 256 * 1024 }, ...overrides };
}
export function preview(body: Input): Preview {
  const local = body.change.action === 'save_definition' ? body.change.definition : definition();
  return { teamName: 'Owned Team', requestId: body.request_id, expectedVersion: body.expected_version, configurationVersion: body.configuration_version,
    difference: { added: [], removed: [], changed: ['root'] }, result: record({ version: body.expected_version + 1, local,
      source: { ...record().source, configurationVersion: body.configuration_version, inventoryFingerprint: body.inventory_fingerprint } }), providerCalled: false, consumerApplied: null, previewOnly: true };
}
export function receipt(body?: Readonly<Input>, overrides: Partial<Receipt> = {}): Receipt {
  return { requestId: body?.request_id ?? requestId, teamName: 'Owned Team', bodyHash: 'b'.repeat(64), version: (body?.expected_version ?? 3) + 1,
    source: { ...record().source, configurationVersion: body?.configuration_version ?? 1 }, action: body?.change.action ?? 'save_definition',
    direction: body?.change.action === 'sync' ? body.change.direction : null, status: 'committed', localHash: 'c'.repeat(64), receiverHash: null,
    localNodeCount: 1, receiverNodeCount: null, difference: { added: [], removed: [], changed: ['root'] }, committedAt: '2026-10-02T10:00:00Z',
    durable: false, immutable: true, providerCalled: false, consumerApplied: null, ...overrides };
}
export function result<T>(data: T): ApiResult<T> { return { data, meta: { source: 'live', elapsedMs: 1, at: Date.now() } }; }
export function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(accept => { resolve = accept; }); return { promise, resolve }; }
