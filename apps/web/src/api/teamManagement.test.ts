import { afterEach, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import { teamManagementApi } from './teamManagement';

afterEach(() => { vi.unstubAllGlobals(); useAuthStore.getState().reset(); localStorage.clear(); });

it('uses guarded native endpoints, stable recovery IDs and strict snake-case change bodies', async () => {
  const requests: { url: string; options?: RequestInit }[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    requests.push({ url: String(input), options }); return Response.json({ scope_id: null, operations: [] });
  }));
  const context = { request_id: '11111111-1111-4111-8111-111111111111', configuration_version: 4, confirm_live: true };
  await teamManagementApi.list(context.request_id);
  await teamManagementApi.observeUsers({ ...context, name_like: 'Alice', cursor: 'opaque cursor' });
  await teamManagementApi.preview({ ...context, expected_state_version: 3,
    change: { action: 'update', team_name: 'Team A', description: '' } });
  await teamManagementApi.getPreview('preview-one');
  await teamManagementApi.apply({ ...context, preview_id: 'preview-one', expected_state_version: 3, confirm_apply: true });
  await teamManagementApi.getOperation('operation-one');
  await teamManagementApi.observe('operation-one', context);
  await teamManagementApi.publish('operation-one', context);
  const base = '/api/v1/alicloud/agentteams/team-management';
  expect(requests.map(request => new URL(request.url, 'http://test.local').pathname)).toEqual([
    base, `${base}/users/observe`, `${base}/previews`, `${base}/previews/preview-one`,
    `${base}/operations`, `${base}/operations/operation-one`, `${base}/operations/operation-one/observe`, `${base}/operations/operation-one/publish`,
  ]);
  expect(new URL(requests[0].url, 'http://test.local').searchParams.get('request_id')).toBe(context.request_id);
  expect(JSON.parse(String(requests[2].options?.body)).change).toEqual({ action: 'update', team_name: 'Team A', description: '' });
  expect(requests.map(request => request.options?.method ?? 'GET')).toEqual(['GET', 'POST', 'POST', 'GET', 'POST', 'GET', 'POST', 'POST']);
});

it('preserves null unknown values and rejects backend failures without simulated team success', async () => {
  const fetcher = vi.fn(async () => Response.json({ scope_id: null, can_prepare: false, items: [{
    team_name: 'unknown', member_names: null, member_names_available: false, current_available: false,
  }], user_directory: null, operations: [] }));
  vi.stubGlobal('fetch', fetcher);
  const result = await teamManagementApi.list();
  expect(result.meta.source).toBe('live'); expect(result.data.scopeId).toBeNull();
  expect(result.data.items[0]).toMatchObject({ memberNames: null, memberNamesAvailable: false, currentAvailable: false });
  fetcher.mockResolvedValue(Response.json({ error: { message: 'Native team backend unavailable' } }, { status: 503 }));
  await expect(teamManagementApi.list()).rejects.toThrow();
});
