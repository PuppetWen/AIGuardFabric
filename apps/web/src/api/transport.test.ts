import { afterEach, expect, it, vi } from 'vitest';
import { callApi } from './transport';

afterEach(() => vi.unstubAllGlobals());

it('sends pagination, search and sort using the server query contract', async () => {
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0 }), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  }));
  vi.stubGlobal('fetch', fetcher);
  await callApi('/api/v1/rules', () => [], { noFallback: true,
    query: { page: 3, pageSize: 25, keyword: '测试 rule', sortBy: 'createdAt', sortOrder: 'desc', enabled: false },
  });
  const url = new URL(String(fetcher.mock.calls[0][0]), 'http://example.test');
  expect(url.searchParams.get('page')).toBe('3');
  expect(url.searchParams.get('page_size')).toBe('25');
  expect(url.searchParams.get('q')).toBe('测试 rule');
  expect(url.searchParams.get('sort')).toBe('-created_at');
  expect(url.searchParams.get('enabled')).toBe('false');
  expect(url.searchParams.has('pageSize')).toBe(false);
  expect(url.searchParams.has('sortOrder')).toBe(false);
});
