import type { ApiResult } from '@/api/dataSource';
import type { MappingIntent, MappingState, PlatformRole, RoleConstraint, WorkerEvidence } from './types';

export const assetId = '10000000-0000-5000-8000-000000000001', roleId = '01921d34-0000-7000-8000-000000000002';
export const requestId = '01921d34-0000-7000-8000-000000000003';
export const role: PlatformRole = { id: roleId, name: 'viewer', displayName: 'Saved tenant viewer', permissions: ['assets:read'], selectable: true, reason: null };
export function worker(overrides: Partial<WorkerEvidence> = {}): WorkerEvidence {
  return { assetId, workerName: 'Actual Worker', teamName: 'Actual Team', cloudRole: 'Actual CloudRole', configurationVersion: 1,
    observedAt: new Date().toISOString(), ...overrides };
}
export function constraint(overrides: Partial<RoleConstraint> = {}): RoleConstraint {
  const evidence = worker();
  return { assetId, version: 3, governed: true, eligibility: 'eligible', reason: null, updatedAt: new Date().toISOString(),
    proof: { configurationVersion: evidence.configurationVersion, mocked: true, region: 'cn-hangzhou', instanceId: 'owned-instance',
      workerName: evidence.workerName, teamName: evidence.teamName, cloudRole: evidence.cloudRole!, observedAt: evidence.observedAt,
      platformRoleId: roleId, department: 'Verified department', dataClass: 'internal' },
    currentQualified: true, currentReason: null, constraint: 'key_scopes_intersection', cloudPermissionGranted: false, ...overrides };
}
export function state(overrides: Partial<MappingState> = {}): MappingState {
  return { catalogAvailable: true, canManage: true, roles: [role], workers: [worker()], items: [], mappedCount: 0,
    note: 'Actual server catalog', adoptionWindowSeconds: 300, permissionTTL: null, providerCalled: false,
    limits: { workers: 512, immutableIntents: 2048 }, ...overrides };
}
export function intent(overrides: Partial<MappingIntent> = {}): MappingIntent {
  return { requestId, assetId, original: constraint({ currentQualified: null }), immutable: true, providerCalled: false, ...overrides };
}
export function result<T>(data: T): ApiResult<T> { return { data, meta: { source: 'live', elapsedMs: 1, at: Date.now() } }; }
export function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(accept => { resolve = accept; }); return { promise, resolve }; }
