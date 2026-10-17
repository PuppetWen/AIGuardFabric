import { describe, expect, it, vi } from 'vitest';
import { newRequestId } from './requestId';

describe('LAN request identifiers', () => {
  it('uses browser entropy without requiring crypto.randomUUID', () => {
    const entropy = vi.fn((bytes: Uint8Array) => bytes.fill(0xff));
    vi.stubGlobal('crypto', { getRandomValues: entropy });
    try {
      expect(newRequestId()).toBe('ffffffff-ffff-4fff-bfff-ffffffffffff');
      expect(entropy).toHaveBeenCalledTimes(1);
    } finally { vi.unstubAllGlobals(); }
  });
});
