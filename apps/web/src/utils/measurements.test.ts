import { describe, expect, it } from 'vitest';
import { compareMeasurements, observationStatus } from './measurements';

describe('measured and unknown values', () => {
  it('keeps unknown last in either Ant Design direction and preserves zero', () => {
    for (const order of ['ascend', 'descend'] as const) {
      const values = [null, 3, 0, Number.NaN];
      values.sort((a, b) => compareMeasurements(a, b, order) * (order === 'ascend' ? 1 : -1));
      expect(values.slice(0, 2)).toEqual(order === 'ascend' ? [0, 3] : [3, 0]);
      expect(values.slice(2).every(value => value === null || Number.isNaN(value))).toBe(true);
    }
  });
  it('ages observations using the reported interval and never invents a timestamp', () => {
    const now = Date.parse('2026-09-22T00:05:00Z');
    const seen = '2026-09-22T00:03:00Z';
    expect(observationStatus(true, seen, 60, now)).toBe(true);
    expect(observationStatus(true, seen, 30, now)).toBe(false);
    expect(observationStatus(true, seen, null, now)).toBe(true);
    expect(observationStatus(true, null, 30, now)).toBeNull();
    expect(observationStatus(true, 'invalid', 30, now)).toBeNull();
    expect(observationStatus(true, '2026-09-22T00:06:00Z', 30, now)).toBeNull();
    expect(observationStatus(false, seen, 60, now)).toBe(false);
  });
});
