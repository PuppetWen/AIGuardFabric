import type { SemanticProfileInput, SemanticSettings } from '@/api/semanticCacheProfile';

export const defaultSettings: SemanticSettings = {
  chat_endpoint_id: '', chat_model: '', chat_model_revision: '',
  embedding_endpoint_id: '', embedding_model: '', embedding_model_revision: '',
  dimensions: 128, send_dimensions: false, max_input_tokens: 2048,
  embedding_micro_per_1k: 0, threshold_ppm: 950000, ttl_seconds: 300,
  classification_floor: 'internal', mode: 'mock_vector',
};
export const validVersion = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const integer = (value: number, min: number, max: number) => Number.isSafeInteger(value) && value >= min && value <= max;
const identifier = (value: string) => /^[A-Za-z0-9_.:/-]{1,128}$/.test(value);
const uuid = (value: string) => /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(value)
  && value !== '00000000-0000-0000-0000-000000000000';

export function validInput(value: SemanticProfileInput): boolean {
  if (!validVersion(value.expected_version) || value.expected_version === Number.MAX_SAFE_INTEGER) return false;
  const s = value.settings;
  if (!s) return !value.enabled;
  return uuid(s.chat_endpoint_id) && uuid(s.embedding_endpoint_id)
    && [s.chat_model, s.chat_model_revision, s.embedding_model, s.embedding_model_revision].every(identifier)
    && integer(s.dimensions, 1, 4096) && integer(s.max_input_tokens, 1, 8192)
    && integer(s.ttl_seconds, 1, 900) && integer(s.threshold_ppm, 900000, 1000000)
    && integer(s.embedding_micro_per_1k, s.mode === 'live' ? 1 : 0, Number.MAX_SAFE_INTEGER)
    && (s.mode === 'live' || (s.mode === 'mock_vector' && s.embedding_micro_per_1k === 0))
    && (s.classification_floor === 'public' || s.classification_floor === 'internal');
}

/** User price is CNY per 1000 tokens; reject fractional microcurrency and imprecise integers. */
export function toMicroCurrency(cny: number | null): number | undefined {
  if (cny === null || !Number.isFinite(cny) || cny < 0) return undefined;
  const scaled = cny * 1_000_000;
  const rounded = Math.round(scaled);
  return Number.isSafeInteger(rounded) && Math.abs(scaled - rounded) < 0.000001 ? rounded : undefined;
}
