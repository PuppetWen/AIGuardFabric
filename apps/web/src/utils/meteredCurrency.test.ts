import { describe, expect, it } from 'vitest';
import { formatCny } from './format';

describe('CNY metering display', () => {
  it('preserves micro-yuan charges without displaying a positive charge as zero', () => {
    expect(formatCny(0.000001, 6)).toBe('¥0.000001');
    expect(formatCny(1.250001, 6)).toBe('¥1.250001');
    expect(formatCny(0, 6)).toBe('¥0.00');
    expect(formatCny(1.25)).toBe('¥1.25');
    expect(formatCny(Number.NaN, 6)).toBe('—');
  });
});
