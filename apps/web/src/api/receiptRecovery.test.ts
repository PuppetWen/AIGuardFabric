import { afterEach, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import { cloudApi } from './cloud';
import { integrationsApi } from './integrations';

const original = useAuthStore.getState();
afterEach(() => { vi.unstubAllGlobals(); useAuthStore.setState(original); });

it('reads pending receipts without writes, then explicitly recovers with empty bodies and preserves provider fields', async () => {
  const requests: { url: string; options?: RequestInit }[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    requests.push({ url: String(input), options });
    return Response.json({ id: 'operation-id', request_id: 'request-id', adapter: 'cms', operation: 'Inspect',
      configuration_version: 7, started_at: '2026-10-01T00:00:00Z', finished_at: null, actor: 'admin',
      status: 'uncertain', mocked: false, completion_state: 'pending_audit', provider_status: 'succeeded',
      receipt: { RequestId: 'provider-id', original_field: { native_key: 'retained' } } });
  }));
  const cloud = await cloudApi.receipt('cms', 'operation-id');
  const integration = await integrationsApi.receipt('webhook', 'operation-id');
  expect(requests).toHaveLength(2);
  expect(requests.every(request => (request.options?.method ?? 'GET') === 'GET')).toBe(true);
  for (const response of [cloud, integration]) {
    expect(response.meta.source).toBe('live');
    expect(response.data).toMatchObject({ requestId: 'request-id', configurationVersion: 7,
      completionState: 'pending_audit', providerStatus: 'succeeded', finishedAt: null,
      receipt: { RequestId: 'provider-id', original_field: { native_key: 'retained' } } });
  }
  await cloudApi.recover('cms', 'operation-id');
  await integrationsApi.recover('webhook', 'operation-id');
  expect(requests.map(request => new URL(request.url, 'http://test.local').pathname)).toEqual([
    '/api/v1/alicloud/connections/cms/operations/operation-id',
    '/api/v1/integrations/adapters/webhook/operations/operation-id',
    '/api/v1/alicloud/connections/cms/operations/operation-id/recover',
    '/api/v1/integrations/adapters/webhook/operations/operation-id/recover',
  ]);
  for (const request of requests.slice(2)) {
    expect(request.options?.method).toBe('POST');
    expect(JSON.parse(String(request.options?.body))).toEqual({});
  }
});

it('surfaces local recovery rejection without a demo receipt or another business call', async () => {
  const fetcher = vi.fn(async (_input: RequestInfo | URL) => Response.json({ error: { message: 'Local audit unavailable' } }, { status: 503 }));
  vi.stubGlobal('fetch', fetcher);
  await expect(integrationsApi.recover('webhook', 'operation-id')).rejects.toThrow();
  expect(fetcher).toHaveBeenCalledOnce();
  expect(String(fetcher.mock.calls[0]?.[0])).toContain('/operations/operation-id/recover');
});
