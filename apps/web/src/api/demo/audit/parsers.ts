import type { Parser, ParserEngine } from '@/types/domain';

import { agoDays } from '../../../utils/time';

/* ------------------------------------------------------------------ */
/* Parsers                                                             */
/* ------------------------------------------------------------------ */

interface ParserSeed {
  id: string;
  name: string;
  engine: ParserEngine;
  successRate: number;
  sampleCount: number;
  sourceId: string;
  version: string;
  updatedDays: number;
  sampleRaw: string;
  sampleParsed: Record<string, string | number>;
}

const parserSeeds: ParserSeed[] = [
  {
    id: 'pars-gateway-json',
    name: 'AI 网关 JSON 解析器',
    engine: 'json-path',
    successRate: 0.9994,
    sampleCount: 12_840_000,
    sourceId: 'src-gateway-mirror',
    version: 'v2.4.0',
    updatedDays: 3,
    sampleRaw:
      '{"ts":"2025-03-18T09:29:58.412Z","tenant":"acme","agent":"客服智能助手 Copilot","mcp":"order-mcp","tool":"get_order","action":"allow","latency_ms":118,"tokens":{"in":1840,"out":210}}',
    sampleParsed: {
      ts: '2025-03-18T09:29:58.412Z',
      tenant: 'acme',
      agent: '客服智能助手 Copilot',
      mcp: 'order-mcp',
      tool: 'get_order',
      action: 'allow',
      latency_ms: 118,
      tokens_in: 1840,
      tokens_out: 210,
    },
  },
  {
    id: 'pars-otlp-mcp',
    name: 'OTLP Span 解析器',
    engine: 'json-path',
    successRate: 0.9988,
    sampleCount: 4_120_000,
    sourceId: 'src-mcp-proxy',
    version: 'v1.9.2',
    updatedDays: 8,
    sampleRaw:
      '{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"mcp-proxy"}}]},"scopeSpans":[{"spans":[{"name":"tools/call","startTimeUnixNano":"1742287798412000000","attributes":[{"key":"mcp.tool.name","value":{"stringValue":"run_command"}},{"key":"agf.decision","value":{"stringValue":"quarantine"}}]}]}]}]}',
    sampleParsed: {
      'service.name': 'mcp-proxy',
      'span.name': 'tools/call',
      'mcp.tool.name': 'run_command',
      'agf.decision': 'quarantine',
      start_time: '2025-03-18T09:29:58.412Z',
    },
  },
  {
    id: 'pars-agent-stdout',
    name: 'Agent 标准输出解析器',
    engine: 'regex-grok',
    successRate: 0.9812,
    sampleCount: 8_640_000,
    sourceId: 'src-agent-stdout',
    version: 'v3.1.0',
    updatedDays: 14,
    sampleRaw:
      '2025-03-18 09:29:58,412 INFO  [agent=copilot session=ses-9f2c8a41] tool_call tool=get_order args={"order_id":"SO20250318001"} elapsed=118ms',
    sampleParsed: {
      timestamp: '2025-03-18 09:29:58,412',
      level: 'INFO',
      agent: 'copilot',
      session: 'ses-9f2c8a41',
      event: 'tool_call',
      tool: 'get_order',
      elapsed_ms: 118,
    },
  },
  {
    id: 'pars-edr-json',
    name: 'EDR 事件解析器',
    engine: 'json-path',
    successRate: 0.9998,
    sampleCount: 2_240_000,
    sourceId: 'src-edr',
    version: 'v1.4.1',
    updatedDays: 20,
    sampleRaw:
      '{"event_id":"edr-7f3a91","hostname":"ops-analyzer.acme.internal","process":"/bin/bash","command_line":"cat /etc/shadow","severity":"high","detect_name":"CredentialAccess"}',
    sampleParsed: {
      event_id: 'edr-7f3a91',
      hostname: 'ops-analyzer.acme.internal',
      process: '/bin/bash',
      command_line: 'cat /etc/shadow',
      severity: 'high',
      detect_name: 'CredentialAccess',
    },
  },
  {
    id: 'pars-syslog-cef',
    name: 'Syslog / CEF 解析器',
    engine: 'cef',
    successRate: 0.9644,
    sampleCount: 6_980_000,
    sourceId: 'src-fw-syslog',
    version: 'v2.0.7',
    updatedDays: 30,
    sampleRaw:
      'CEF:0|Acme|Firewall|4.2|1001|Outbound connection blocked|7|src=10.20.31.17 dst=47.98.12.33 dpt=4444 proto=TCP act=block',
    sampleParsed: {
      device_vendor: 'Acme',
      device_product: 'Firewall',
      signature_id: 1001,
      name: 'Outbound connection blocked',
      severity: 7,
      src: '10.20.31.17',
      dst: '47.98.12.33',
      dpt: 4444,
      proto: 'TCP',
      act: 'block',
    },
  },
  {
    id: 'pars-cef-dlp',
    name: 'DLP CEF 解析器',
    engine: 'cef',
    successRate: 0.8721,
    sampleCount: 420_000,
    sourceId: 'src-dlp',
    version: 'v1.0.3',
    updatedDays: 60,
    sampleRaw: 'CEF:0|Acme|DLP|1.2.7|2003|Sensitive data egress|9|fname=orders.csv fsize=214000 dst=attacker.example',
    sampleParsed: {
      device_vendor: 'Acme',
      device_product: 'DLP',
      signature_id: 2003,
      name: 'Sensitive data egress',
      severity: 9,
      fname: 'orders.csv',
      fsize: 214_000,
      dst: 'attacker.example',
    },
  },
  {
    id: 'pars-cloudtrail-json',
    name: 'ActionTrail 解析器',
    engine: 'json-path',
    successRate: 0.9991,
    sampleCount: 1_240_000,
    sourceId: 'src-cloudtrail',
    version: 'v1.2.0',
    updatedDays: 11,
    sampleRaw:
      '{"eventTime":"2025-03-18T09:24:00Z","eventName":"ListAgentTeams","userIdentity":{"type":"assumed-role","arn":"acs:ram::1234:role/acs-aigf-readonly"},"sourceIpAddress":"10.20.5.9","requestParameters":{"region":"cn-hangzhou"}}',
    sampleParsed: {
      eventTime: '2025-03-18T09:24:00Z',
      eventName: 'ListAgentTeams',
      user_type: 'assumed-role',
      user_arn: 'acs:ram::1234:role/acs-aigf-readonly',
      sourceIpAddress: '10.20.5.9',
      region: 'cn-hangzhou',
    },
  },
  {
    id: 'pars-llm-assist',
    name: 'LLM 辅助兜底解析器',
    engine: 'llm-assisted',
    successRate: 0.9136,
    sampleCount: 96_000,
    sourceId: 'src-gateway-mirror',
    version: 'v0.6.0',
    updatedDays: 5,
    sampleRaw: '<134>Mar 18 09:29:58 agf-edge model=qwen-plus cost=0.0042 msg="upstream latency spike, falling back"',
    sampleParsed: {
      host: 'agf-edge',
      model: 'qwen-plus',
      cost: 0.0042,
      message: 'upstream latency spike, falling back',
    },
  },
];

export const demoParsers: Parser[] = parserSeeds.map((seed) => ({
  id: seed.id,
  name: seed.name,
  engine: seed.engine,
  successRate: seed.successRate,
  sampleCount: seed.sampleCount,
  sourceId: seed.sourceId,
  version: seed.version,
  updatedAt: agoDays(seed.updatedDays),
  sampleRaw: seed.sampleRaw,
  sampleParsed: seed.sampleParsed,
}));
