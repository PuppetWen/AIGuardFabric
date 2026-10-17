/** Helpers for converting server resources into console views. */
export type ApiObject = Record<string, unknown>;

export function object(value: unknown): ApiObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as ApiObject : {};
}

export function text(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : typeof value === 'number' ? String(value) : fallback;
}

export function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function strings(value: unknown): string[] {
  return list(value).filter((item): item is string => typeof item === 'string');
}

/** Missing measurements stay absent rather than becoming fabricated zeroes. */
export function measurement(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

export function number(value: unknown, fallback = 0): number {
  return measurement(value) ?? fallback;
}

export function mapped(value: unknown, values: Record<string, string>, fallback = ''): string {
  const key = text(value).replaceAll('_', '-');
  return values[key] ?? (key || fallback);
}

export function page(value: unknown, adapt: (row: ApiObject) => unknown): unknown {
  const envelope = object(value);
  return { ...envelope, items: list(envelope.items).map((row) => adapt(object(row))) };
}

export function riskDomain(value: unknown): string {
  return mapped(value, {
    'prompt-attack': 'runtime', 'tool-abuse': 'runtime',
    'credential-leak': 'identity', 'rag-poison': 'data', 'model-data': 'data',
  });
}

export function policyAction(value: unknown): string {
  return mapped(value, { audit: 'alert', redact: 'mask', quota: 'throttle', degrade: 'redirect', isolate: 'quarantine' });
}
