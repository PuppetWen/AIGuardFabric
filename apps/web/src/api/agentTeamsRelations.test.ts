import { afterEach, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import { operationsEndpoints } from './operationsEndpoints';

afterEach(() => { vi.unstubAllGlobals(); useAuthStore.getState().reset(); localStorage.clear(); });

it('preserves null counts and independent relation, human-roster and DAG availability from the live API', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => Response.json([
    { id: 'unknown-team', member_count: null, relationship_available: false, relationship_evidence: 'unverified', members: [],
      human_members: [], human_members_available: false, human_member_count: null, dag: [], dag_available: false, dag_evidence: 'not-provided' },
    { id: 'empty-team', member_count: 0, relationship_available: true, relationship_evidence: 'worker-groups', members: [],
      human_members: [], human_members_available: true, human_member_count: 0, dag: [], dag_available: false },
  ])));
  const response = await operationsEndpoints.agentTeams();
  expect(response.meta.source).toBe('live');
  expect(response.data[0]).toMatchObject({ memberCount: null, relationshipAvailable: false, relationshipEvidence: 'unverified',
    humanMembersAvailable: false, humanMemberCount: null, dagAvailable: false, dagEvidence: 'not-provided' });
  expect(response.data[1]).toMatchObject({ memberCount: 0, relationshipAvailable: true, relationshipEvidence: 'worker-groups',
    humanMembersAvailable: true, humanMemberCount: 0 });
});

it('retains provider roles as strings or null without manufacturing platform roles from cloud users', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => Response.json([{ id: 'known-team', memberCount: 2,
    relationshipAvailable: true, relationshipEvidence: 'team-worker-names', members: [
      { id: 'worker-one', name: 'shared-name', role: 'custom-role', cloudRole: 'custom-role' },
      { id: 'worker-two', name: 'unknown-role', role: null, cloudRole: null },
    ], humanMembersAvailable: true, humanMembers: [{ name: 'shared-name' }], humanMemberCount: 1 }])));
  const response = await operationsEndpoints.agentTeams();
  expect(response.data[0].members.map(member => member.cloudRole)).toEqual(['custom-role', null]);
  expect(response.data[0].members.map(member => member.name)).toEqual(['shared-name', 'unknown-role']);
  expect(response.data[0].humanMembers).toEqual([{ name: 'shared-name' }]);
});
