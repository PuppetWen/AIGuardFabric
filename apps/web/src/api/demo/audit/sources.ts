import type { AdapterHealth, IngestProtocol, LogSource } from '@/types/domain';

import { agoMinutes } from '../../../utils/time';

/* ------------------------------------------------------------------ */
/* Log sources                                                         */
/* ------------------------------------------------------------------ */

/** All 16 supported ingest protocols, in wizard order. */
export const INGEST_PROTOCOLS: IngestProtocol[] = [
  'syslog-udp',
  'syslog-tcp',
  'syslog-tls',
  'syslog-cef',
  'kafka',
  'http-webhook',
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

interface SourceSeed {
  id: string;
  name: string;
  protocol: IngestProtocol;
  mode: LogSource['mode'];
  endpoint: string;
  parserId: string;
  health: AdapterHealth;
  eventsPerSec: number;
  lastEventMinutes: number;
  droppedEvents24h: number;
  enabled: boolean;
  tls: boolean;
}

const sourceSeeds: SourceSeed[] = [
  {
    id: 'src-gateway-mirror',
    name: 'AI 网关镜像流量',
    protocol: 'kafka',
    mode: 'pull',
    endpoint: 'kafka://agf-broker.intra.acme:9092/topic=agf.gateway.mirror',
    parserId: 'pars-gateway-json',
    health: 'healthy',
    eventsPerSec: 4_820,
    lastEventMinutes: 0.1,
    droppedEvents24h: 0,
    enabled: true,
    tls: true,
  },
  {
    id: 'src-mcp-proxy',
    name: 'MCP 代理审计流',
    protocol: 'otlp-grpc',
    mode: 'push',
    endpoint: 'grpc://agf-collector.intra.acme:4317',
    parserId: 'pars-otlp-mcp',
    health: 'healthy',
    eventsPerSec: 2_140,
    lastEventMinutes: 0.1,
    droppedEvents24h: 12,
    enabled: true,
    tls: true,
  },
  {
    id: 'src-agent-stdout',
    name: 'Agent 容器标准输出',
    protocol: 'file-tail',
    mode: 'pull',
    endpoint: '/var/log/containers/*.log',
    parserId: 'pars-agent-stdout',
    health: 'healthy',
    eventsPerSec: 1_680,
    lastEventMinutes: 0.2,
    droppedEvents24h: 0,
    enabled: true,
    tls: false,
  },
  {
    id: 'src-edr',
    name: 'EDR 终端事件',
    protocol: 'http-webhook',
    mode: 'push',
    endpoint: 'https://agf-collector.intra.acme/hooks/edr',
    parserId: 'pars-edr-json',
    health: 'healthy',
    eventsPerSec: 320,
    lastEventMinutes: 0.6,
    droppedEvents24h: 3,
    enabled: true,
    tls: true,
  },
  {
    id: 'src-fw-syslog',
    name: '边界防火墙 Syslog',
    protocol: 'syslog-tls',
    mode: 'push',
    endpoint: 'tls://0.0.0.0:6514',
    parserId: 'pars-syslog-cef',
    health: 'degraded',
    eventsPerSec: 940,
    lastEventMinutes: 1.4,
    droppedEvents24h: 1_284,
    enabled: true,
    tls: true,
  },
  {
    id: 'src-dlp',
    name: 'DLP 探针事件',
    protocol: 'syslog-cef',
    mode: 'push',
    endpoint: 'udp://0.0.0.0:5140',
    parserId: 'pars-cef-dlp',
    health: 'unhealthy',
    eventsPerSec: 0,
    lastEventMinutes: 540,
    droppedEvents24h: 0,
    enabled: false,
    tls: false,
  },
  {
    id: 'src-cloudtrail',
    name: '阿里云 ActionTrail 投递桶',
    protocol: 'cloudtrail-s3',
    mode: 'pull',
    endpoint: 'oss://acme-actiontrail-cn-hangzhou/Actiontrail/',
    parserId: 'pars-cloudtrail-json',
    health: 'healthy',
    eventsPerSec: 46,
    lastEventMinutes: 5,
    droppedEvents24h: 0,
    enabled: true,
    tls: true,
  },
  {
    id: 'src-otel-http',
    name: 'Agent 自埋点（OTLP/HTTP）',
    protocol: 'otlp-http',
    mode: 'push',
    endpoint: 'https://agf-collector.intra.acme/v1/traces',
    parserId: 'pars-otlp-mcp',
    health: 'healthy',
    eventsPerSec: 760,
    lastEventMinutes: 0.3,
    droppedEvents24h: 0,
    enabled: true,
    tls: true,
  },
  {
    id: 'src-fluentd',
    name: 'Fluentd 聚合流',
    protocol: 'fluentd',
    mode: 'push',
    endpoint: 'tcp://0.0.0.0:24224',
    parserId: 'pars-agent-stdout',
    health: 'healthy',
    eventsPerSec: 1_120,
    lastEventMinutes: 0.2,
    droppedEvents24h: 8,
    enabled: true,
    tls: true,
  },
  {
    id: 'src-nats',
    name: '内部事件总线（NATS）',
    protocol: 'nats',
    mode: 'pull',
    endpoint: 'nats://nats.intra.acme:4222/subject=agf.events.>',
    parserId: 'pars-gateway-json',
    health: 'unknown',
    eventsPerSec: 0,
    lastEventMinutes: 2_880,
    droppedEvents24h: 0,
    enabled: false,
    tls: true,
  },
];

export const demoLogSources: LogSource[] = sourceSeeds.map((seed) => ({
  id: seed.id,
  name: seed.name,
  protocol: seed.protocol,
  mode: seed.mode,
  endpoint: seed.endpoint,
  parserId: seed.parserId,
  health: seed.health,
  eventsPerSec: seed.eventsPerSec,
  lastEventAt: agoMinutes(seed.lastEventMinutes),
  droppedEvents24h: seed.droppedEvents24h,
  enabled: seed.enabled,
  tls: seed.tls,
}));
