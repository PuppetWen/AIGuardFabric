import type { LogSource } from '@/types/domain';

export const sourceTransportControls = (receiver: string) => ({
  cidrs: ['syslog-udp', 'syslog-tcp', 'syslog-tls', 'otlp', 'otlp-traces', 'otlp-metrics',
    'otlp-grpc', 'otlp-grpc-traces', 'otlp-grpc-metrics'].includes(receiver),
  mtls: ['syslog-tls', 'otlp-grpc', 'otlp-grpc-traces', 'otlp-grpc-metrics'].includes(receiver),
});

export const NATIVE_RECEIVERS = [
  'syslog-udp', 'syslog-tcp', 'syslog-tls', 'webhook', 'kafka', 'pulsar', 'pulsar-native',
  'nats-jetstream', 'snmp-trap', 'mqtt', 'object-pull', 'sql-pull',
  'otlp', 'otlp-traces', 'otlp-metrics', 'otlp-grpc', 'otlp-grpc-traces', 'otlp-grpc-metrics',
];

const SETTINGS: Record<string, string[]> = {
  'syslog-udp': [], 'syslog-tcp': [],
  'syslog-tls': ['AGF_SYSLOG_TLS_PORT', 'AGF_SYSLOG_TLS_CERT', 'AGF_SYSLOG_TLS_KEY'],
  webhook: ['AGF_WEBHOOK_TOKEN'],
  kafka: ['AGF_INGEST_KAFKA_BROKERS', 'AGF_INGEST_KAFKA_TOPIC', 'AGF_INGEST_KAFKA_GROUP_ID'],
  pulsar: ['AGF_INGEST_PULSAR_SERVICE_URL', 'AGF_INGEST_PULSAR_TOPIC', 'AGF_INGEST_PULSAR_SUBSCRIPTION'],
  'pulsar-native': ['AGF_INGEST_PULSAR_URL', 'AGF_INGEST_PULSAR_TOPIC', 'AGF_INGEST_PULSAR_SUBSCRIPTION'],
  'nats-jetstream': ['AGF_INGEST_JETSTREAM_URL', 'AGF_INGEST_JETSTREAM_IDENTITY', 'AGF_INGEST_JETSTREAM_SUBJECT'],
  'snmp-trap': ['AGF_INGEST_SNMP_LISTEN', 'AGF_INGEST_SNMP_COMMUNITY', 'AGF_INGEST_SNMP_VERSION'],
  mqtt: ['AGF_INGEST_MQTT_BROKER', 'AGF_INGEST_MQTT_TOPIC', 'AGF_INGEST_MQTT_CLIENT_ID'],
  'object-pull': ['AGF_INGEST_OBJECT_PULL_BUCKET'],
  'sql-pull': ['AGF_INGEST_SQL_DSN', 'AGF_INGEST_SQL_QUERY', 'AGF_INGEST_SQL_CURSOR_FIELD', 'AGF_INGEST_SQL_CURSOR_TYPE'],
  otlp: ['AGF_INGEST_OTLP_ENABLED'], 'otlp-traces': ['AGF_INGEST_OTLP_ENABLED'],
  'otlp-grpc-traces': ['AGF_INGEST_OTLP_GRPC_ENABLED'], 'otlp-grpc-metrics': ['AGF_INGEST_OTLP_GRPC_ENABLED'],
  'otlp-metrics': ['AGF_INGEST_OTLP_ENABLED'], 'otlp-grpc': ['AGF_INGEST_OTLP_GRPC_ENABLED'],
};

export function nativeCompose(source: Pick<LogSource, 'nativeReceiver' | 'id' | 'requireMtls'>, tenant: string): string {
  const receiver = source.nativeReceiver ?? '';
  const security = !source.requireMtls ? [] : receiver === 'syslog-tls' ? ['AGF_SYSLOG_TLS_CLIENT_CA']
    : receiver.startsWith('otlp-grpc') ? ['AGF_INGEST_OTLP_GRPC_TLS', 'AGF_INGEST_OTLP_GRPC_TLS_CERT',
      'AGF_INGEST_OTLP_GRPC_TLS_KEY', 'AGF_INGEST_OTLP_GRPC_TLS_CLIENT_CA'] : [];
  return [
    'services:', '  agf-ingest:', '    environment:',
    '      AGF_INGEST_SQL_SINK: "1"',
    '      AGF_INGEST_TENANT_ID: ' + JSON.stringify(tenant),
    "      AGF_INGEST_SOURCE_IDS: '" + JSON.stringify({ [receiver]: source.id }) + "'",
    ...[...(SETTINGS[receiver] ?? []), ...security].map((key) => '      ' + key + ': ${' + key + ':?请在项目 .env 中填写 ' + key + '}'),
  ].join('\n');
}

