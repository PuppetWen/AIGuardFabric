import { callApi } from './transport';

export interface SemanticSettings {
  chat_endpoint_id: string;
  chat_model: string;
  chat_model_revision: string;
  embedding_endpoint_id: string;
  embedding_model: string;
  embedding_model_revision: string;
  dimensions: number;
  send_dimensions: boolean;
  max_input_tokens: number;
  embedding_micro_per_1k: number;
  threshold_ppm: number;
  ttl_seconds: number;
  classification_floor: 'public' | 'internal';
  mode: 'live' | 'mock_vector';
}
export interface SemanticProfile {
  version: number;
  enabled: boolean;
  settings: SemanticSettings | null;
  placementVerified: boolean;
  providerWeightsRevisionVerified: boolean;
}
export interface SemanticProfileInput {
  expected_version: number;
  enabled: boolean;
  settings: SemanticSettings | null;
}
const path = '/api/v1/models/semantic-cache/profile';
const unavailable = (): never => { throw new Error('请连接后端服务 / Connect to the backend'); };
export const semanticProfileApi = {
  read: () => callApi<SemanticProfile>(path, unavailable, { noFallback: true, opaqueKeys: ['settings'] }),
  save: (body: SemanticProfileInput) => callApi<SemanticProfile>(path, unavailable,
    { method: 'PUT', body, noFallback: true, opaqueKeys: ['settings'] }),
};
