import type { OnboardingPlan, OnboardingMode } from './domain';
export type OnboardingTarget = 'collector' | 'mcp-stdio' | 'python-startup' | 'node-cjs-startup' | 'model-openai' | 'model-anthropic' | 'mcp-http';
export interface StartupFields {
  source_id: string; binding_id: string; worker: string; team: string | null; kind: 'task' | 'call';
  callee_worker: string | null; callee_team: string | null; operation: string; module: string; callable: string;
  entry: string; sdk_directory: string; spool_directory: string; configuration_file: string;
  target_file: string | null; async_mode: string | null;
}
export interface PlanRequest {
  agent_id?: string; mode: OnboardingMode; target: OnboardingTarget; platform: string; locale: string;
  public_base: string; model?: string; sdk?: StartupFields;
}
export interface SourceChoice {
  sourceId: string; bindingId: string; scopeId: string; mocked: boolean; name: string;
  workers: { name: string; teams: string[] }[];
}
export interface ConnectionPlan extends OnboardingPlan {
  target: OnboardingTarget; ready: boolean; availableTargets: OnboardingTarget[];
  links: { label: string; href: string }[]; sdkSources: SourceChoice[];
  configurationJson: string | null; keyEnv: string | null;
}
export const targetChoices: Record<OnboardingMode, OnboardingTarget[]> = {
  sidecar: ['collector', 'mcp-stdio'], 'sdk-inject': ['python-startup', 'node-cjs-startup'],
  'gateway-register': ['model-openai', 'model-anthropic', 'mcp-http'],
};
