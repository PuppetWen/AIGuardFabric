import { expect, it } from 'vitest';
import { payload, receiptValid, stateValid } from './validation';
import { receipt, requestId, state } from './testFixtures';
it('rejects non-finite metrics, unknown shapes and UTF8 name overflow', () => {
  expect(() => payload('metric', 'x', '', NaN, '{}')).toThrow();
  expect(() => payload('metric', 'x', '', 1, '[]')).toThrow();
  expect(() => payload('event', '中'.repeat(43), 'content', 0, '{}')).toThrow();
  expect(payload('metric', 'x', '', 1, '{"tenant":"owned"}')).toMatchObject({ kind: 'metric', value: 1, dimensions: { tenant: 'owned' } });
});
it('validates original receipt identity and exact safe state before unlocking', () => {
  expect(receiptValid(receipt(), requestId)).toBe(true); expect(receiptValid(receipt(), crypto.randomUUID())).toBe(false);
  expect(stateValid(state())).toBe(true); expect(stateValid(state({ generation: Number.MAX_SAFE_INTEGER + 1 }))).toBe(false);
});
