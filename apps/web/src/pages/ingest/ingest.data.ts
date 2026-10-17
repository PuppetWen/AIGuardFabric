import type { IngestProtocol, ParserEngine } from '@/types/domain';

export const PROTOCOLS: IngestProtocol[] = [
  'syslog-udp',
  'syslog-tcp',
  'syslog-tls',
  'syslog-cef',
  'kafka',
  'http-webhook',
  'http-pull',
  'file-tail',
  'fluentd',
  'otlp-grpc',
  'otlp-http',
  'splunk-hec',
  'elastic-beats',
  'mqtt',
  'nats',
  'amqp',
  'cloudtrail-s3',
];

export const ENGINES: ParserEngine[] = ['grok', 'regex', 'json-path', 'jq', 'syslog', 'kv', 'cef', 'leef', 'gelf', 'csv', 'cel', 'plugin', 'ai-inferred'];

export interface NewSourceValues {
  name: string;
  protocol: string;
  nativeReceiver?: string;
  endpoint: string;
  parserId?: string;
  enabled: boolean;
  pollIntervalSecs: number;
  headersText?: string;
  allowedCidrsText?: string;
  requireMtls?: boolean;
}
