import '@testing-library/jest-dom/vitest';

import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';

/**
 * 本文件同时服务两种测试环境：
 *   * 默认的 jsdom（页面/组件测试）；
 *   * 少数用 `// @vitest-environment node` 声明的联调回归（`src/api/client.live.test.ts`）——
 *     这类测试要打真实后端，必须用 Node 原生的 fetch/AbortController，jsdom 的
 *     global 会把它们替换成不兼容的实现，导致请求直接抛错。
 * 因此所有 DOM 相关的桩都要按"是否有 window"做守卫。
 */
const hasDom = typeof window !== 'undefined';

// antd probes matchMedia / ResizeObserver / getComputedStyle in jsdom.
if (hasDom && !window.matchMedia) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }),
  });
}

class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}

if (hasDom && !('ResizeObserver' in globalThis)) {
  Object.defineProperty(globalThis, 'ResizeObserver', {
    writable: true,
    value: ResizeObserverStub,
  });
}

if (hasDom && !('IntersectionObserver' in globalThis)) {
  class IntersectionObserverStub {
    root = null;
    rootMargin = '';
    thresholds: number[] = [];
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
    takeRecords(): [] {
      return [];
    }
  }
  Object.defineProperty(globalThis, 'IntersectionObserver', {
    writable: true,
    value: IntersectionObserverStub,
  });
}

afterEach(() => {
  if (hasDom) {
    cleanup();
  }
});
