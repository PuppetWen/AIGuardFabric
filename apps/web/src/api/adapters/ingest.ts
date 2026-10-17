import { mapped, measurement, number, object, text, type ApiObject } from './shared';

export function source(raw: ApiObject): ApiObject {
  return {
    ...raw, name: text(raw.name ?? raw.receiver ?? raw.id),
    protocol: mapped(raw.nativeReceiver ?? raw.protocol, {
      webhook: 'http-webhook', syslog: 'syslog-tcp', file: 'file-tail',
      otlp: 'otlp-http', 's3-pull': 'cloudtrail-s3',
    }),
    mode: raw.mode ?? 'push', endpoint: text(raw.endpoint ?? object(raw.connection).endpoint ?? raw.listener),
    parserId: text(raw.parserId),
    health: mapped(raw.health ?? raw.status, { ready: 'healthy', disabled: 'unknown', unconfigured: 'unknown', unavailable: 'unhealthy' }, 'unknown'),
    eventsPerSec: measurement(raw.eventsPerSec), droppedEvents24h: measurement(raw.droppedEvents24h),
    lastEventAt: text(raw.lastEventAt), enabled: raw.enabled ?? raw.status === 'ready',
    tls: raw.tls ?? object(raw.connection).tls ?? text(raw.protocol).includes('tls'),
  };
}

export function parser(raw: ApiObject): ApiObject {
  return {
    ...raw,
    engine: mapped(raw.engine, { json: 'json-path', jsonpath: 'json-path', ai: 'ai-inferred' }),
    version: text(raw.version),
    sampleCount: raw.sampleCount ?? number(raw.successCount) + number(raw.failureCount),
    sourceId: text(raw.sourceId), updatedAt: text(raw.updatedAt ?? raw.lastUsedAt),
    sampleRaw: text(raw.sampleRaw), sampleParsed: object(raw.sampleParsed),
  };
}
