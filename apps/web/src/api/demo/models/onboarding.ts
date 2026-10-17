import type { OnboardingMode, OnboardingPlan } from '@/types/domain';

/** Demo cannot supply executable deployment commands or published artifacts. */
export function buildOnboardingPlan(agentId: string, mode: OnboardingMode): OnboardingPlan {
  return { agentId, mode, endpoint: '', artifactUrl: null, artifactSha256: null,
    platform: 'windows-amd64', envSnippet: '', steps: [], estimatedDowntimeSec: null, rollout: 'manual' };
}
