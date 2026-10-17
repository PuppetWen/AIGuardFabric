import type { Payload, QueueState, Receipt } from './types';
export const uuid = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
const integer = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
export function stateValid(value: QueueState): boolean {
  return integer(value.generation) && integer(value.total) && integer(value.page) && value.page > 0
    && Array.isArray(value.items) && value.items.every(item => uuid(item.id) && integer(item.attemptCount))
    && value.automaticRetry === false && value.exactlyOnce === false
    && (value.source === null || (uuid(value.source.configurationId) && integer(value.source.configurationVersion)
      && value.source.configurationVersion > 0 && ['mock', 'live', 'loopback_test'].includes(value.source.transportMode)));
}
export function receiptValid(value: Receipt, id: string, purpose?: Receipt['purpose']): boolean {
  return value.id === id && uuid(id) && (purpose === undefined || value.purpose === purpose) && value.immutableIntent === true && value.automaticRetry === false
    && ['enqueue', 'send', 'archive'].includes(value.purpose) && integer(value.generation)
    && Array.isArray(value.itemIds) && value.itemIds.every(uuid) && Array.isArray(value.originalAttempts)
    && value.originalAttempts.every(attempt => attempt.requestId === id && uuid(attempt.id));
}
export function payload(kind: 'event' | 'metric', name: string, content: string, metric: number | null, dimensions: string): Payload {
  const bytes = (text: string) => new TextEncoder().encode(text).length;
  const controlled = (text: string) => Array.from(text).some(c => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127);
  if (!name || bytes(name) > 128 || controlled(name)) throw new Error('invalid');
  if (kind === 'event') {
    if (!content || bytes(content) > 4096) throw new Error('invalid');
    return { kind, name, content, at: new Date().toISOString() };
  }
  const parsed: unknown = JSON.parse(dimensions);
  if (metric === null || !Number.isFinite(metric) || !parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('invalid');
  const fields = Object.entries(parsed);
  if (fields.length > 16 || fields.some(([key, value]) => !key || bytes(key) > 128 || controlled(key)
    || typeof value !== 'string' || !value || bytes(value) > 256 || controlled(value))) throw new Error('invalid');
  return { kind, name, value: metric, dimensions: Object.fromEntries(fields), at: new Date().toISOString() };
}
