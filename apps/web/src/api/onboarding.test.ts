import { expect, it, vi } from 'vitest';
import { callApi } from './transport';
import { onboardingApi } from './onboarding';
import type { PlanRequest } from '@/types/onboarding';
vi.mock('./transport', () => ({ callApi: vi.fn() }));
it('keeps read-only GET distinct from strict POST, preserves opaque JSON and never supplies a fallback', () => {
  const signal = new AbortController().signal, body: PlanRequest = { mode: 'sdk-inject', target: 'node-cjs-startup',
    platform: 'windows-amd64', locale: 'en-US', public_base: 'https://platform.example.test' };
  onboardingApi.choices(body, signal); onboardingApi.plan(body, signal);
  expect(callApi).toHaveBeenNthCalledWith(1, '/api/v1/agents/onboarding-plan', expect.any(Function), { noFallback: true, query: body, signal });
  expect(callApi).toHaveBeenNthCalledWith(2, '/api/v1/agents/onboarding-plan', expect.any(Function), { noFallback: true, method: 'POST', body, signal });
  expect(() => vi.mocked(callApi).mock.calls[0][1]()).toThrow('require the current server');
});
