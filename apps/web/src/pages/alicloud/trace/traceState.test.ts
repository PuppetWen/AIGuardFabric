import { describe, expect, it } from 'vitest';
import { traceQuery } from './traceState';
import type { TraceDraft } from '@/types/agentTeamsTrace';

const now = Date.parse('2026-09-30T12:00:00Z');
const draft: TraceDraft = { traceId: ' sdk:observed-root.1 ', from: '2026-09-29T12:00:00', until: '2026-09-30T12:00:00', limit: 50 };
describe('Explicit Trace query boundaries', () => {
  it('preserves valid opaque identifiers and sends UTC seconds as exact RFC3339 bounds', () => {
    expect(traceQuery(draft, now)).toEqual({ traceId: 'sdk:observed-root.1', from: '2026-09-29T12:00:00.000Z',
      until: '2026-09-30T12:00:00.000Z', limit: 50 });
    expect(traceQuery({ ...draft, from: '2026-08-31T12:00:00', limit: 200 }, now).limit).toBe(200);
    expect(traceQuery({ ...draft, until: '2026-09-30T12:01:00' }, now).until).toContain('12:01:00');
    expect(traceQuery({ ...draft, from: '2026-09-29T12:00' }, now).from).toBe('2026-09-29T12:00:00.000Z');
  });
  it.each([
    { traceId: '' }, { traceId: 'private/unsafe' }, { traceId: 'x'.repeat(129) },
    { from: '2026-09-30T12:00:00' }, { from: '2026-08-31T11:59:59' },
    { until: '2026-09-30T12:01:01' }, { from: '2026-02-30T12:00:00' },
    { from: '2026-09-29T12' }, { limit: 0 }, { limit: 201 }, { limit: 1.5 },
  ])('refuses invalid query locally before any network call: %j', patch => {
    expect(() => traceQuery({ ...draft, ...patch }, now)).toThrow();
  });
});
