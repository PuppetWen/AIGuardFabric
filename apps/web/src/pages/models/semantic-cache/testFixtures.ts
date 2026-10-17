import type { ApiResult } from '@/api/dataSource';
import type { SemanticProfile } from '@/api/semanticCacheProfile';
import type { GatewayEndpoint } from '@/api/gateway';
import { defaultSettings } from './validation';

export const chatId = '44a987fb-665e-46bf-94dd-2107399c92b1';
export const embeddingId = '8b11dd68-fc14-441b-bb8e-49f9baae1522';
export const result = <T,>(data: T): ApiResult<T> => ({ data, meta: { source: 'live', elapsedMs: 1, at: Date.now() } });
export function profile(overrides: Partial<SemanticProfile> = {}): SemanticProfile {
  return { version: 7, enabled: true, placementVerified: false, providerWeightsRevisionVerified: false,
    settings: { ...defaultSettings, chat_endpoint_id: chatId, chat_model: 'mock-chat', chat_model_revision: 'chat-r1',
      embedding_endpoint_id: embeddingId, embedding_model: 'mock-embedding', embedding_model_revision: 'embedding-r1' }, ...overrides };
}
export function endpoint(id = chatId, model = 'mock-chat'): GatewayEndpoint {
  return { id, version: 1, name: model, provider: 'mock', model, baseUrl: 'http://mock.invalid/v1',
    localDeployment: true, maxDataClass: 'internal', enabled: true, credentialConfigured: false, mocked: true,
    pricing: { promptMicroPer1k: 0, completionMicroPer1k: 0, cachedPromptMicroPer1k: 0 } };
}
export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(value => { resolve = value; });
  return { promise, resolve };
}
