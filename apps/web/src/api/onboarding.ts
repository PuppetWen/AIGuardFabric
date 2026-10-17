import { callApi } from './transport';
import type { Agent, ListQuery, Paged } from '@/types/domain';
import type { ConnectionPlan, PlanRequest } from '@/types/onboarding';
const path = '/api/v1/agents/onboarding-plan';
const requireServer = (): never => { throw new Error('Connection plans require the current server'); };
export const onboardingApi = {
  agents: (query: ListQuery) => callApi<Paged<Agent>>('/api/v1/agents', requireServer, { noFallback: true, query: { ...query } }),
  choices: (input: Omit<PlanRequest, 'sdk'>, signal: AbortSignal) => callApi<ConnectionPlan>(path, requireServer,
    { noFallback: true, query: { ...input }, signal }),
  plan: (input: PlanRequest, signal: AbortSignal) => callApi<ConnectionPlan>(path, requireServer,
    { noFallback: true, method: 'POST', body: input, signal }),
};
