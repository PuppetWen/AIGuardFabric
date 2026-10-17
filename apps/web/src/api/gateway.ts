import { callApi } from './transport';

export interface GatewayEndpoint {
  id: string;
  version: number;
  name: string;
  provider: string;
  model: string;
  baseUrl: string;
  apiVersion?: string;
  localDeployment: boolean;
  maxDataClass: string;
  enabled: boolean;
  credentialConfigured: boolean;
  mocked: boolean;
  pricing: { promptMicroPer1k: number; completionMicroPer1k: number; cachedPromptMicroPer1k: number };
}

export interface GatewayProvider {
  value: string;
  suggestedBaseUrl: string;
  requiresCustomBaseUrl: boolean;
  localDeployment: boolean;
}

export interface EndpointInput {
  expected_version: number;
  name: string;
  provider: string;
  model: string;
  base_url: string;
  api_key?: string;
  api_version?: string;
  local_deployment: boolean;
  max_data_class: string;
  enabled: boolean;
  pricing?: { prompt_micro_per_1k: number; completion_micro_per_1k: number; cached_prompt_micro_per_1k: number };
}

const unavailable = (): never => { throw new Error('请连接后端服务'); };
export const gatewayApi = {
  list: () => callApi<{ items: GatewayEndpoint[] }>('/api/v1/gateway/endpoints', unavailable, { noFallback: true }),
  providers: () => callApi<{ items: GatewayProvider[] }>('/api/v1/gateway/providers', unavailable, { noFallback: true }),
  save: (id: string | undefined, body: EndpointInput) => callApi<GatewayEndpoint>(
    `/api/v1/gateway/endpoints${id ? `/${encodeURIComponent(id)}` : ''}`,
    unavailable, { method: id ? 'PUT' : 'POST', body, noFallback: true }),
  remove: (id: string, version: number) => callApi(`/api/v1/gateway/endpoints/${encodeURIComponent(id)}`, unavailable,
    { method: 'DELETE', query: { expected_version: version }, noFallback: true }),
  test: (model: string) => callApi<{ choices: { message: { content: string } }[] }>(
    '/api/v1/chat/completions', unavailable,
    { method: 'POST', body: { model, messages: [{ role: 'user', content: 'Reply with OK.' }], max_tokens: 16 },
      noFallback: true, timeoutMs: 120_000 }),
};
