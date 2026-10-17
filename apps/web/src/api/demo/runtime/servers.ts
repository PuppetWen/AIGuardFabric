import type { McpServer, McpTransport } from '@/types/domain';

import { agoDays, agoMinutes } from '../../../utils/time';
import { ASSET_ID } from '../assets';

/* ------------------------------------------------------------------ */
/* MCP servers                                                         */
/* ------------------------------------------------------------------ */

interface McpSeed {
  id: string;
  assetId: string;
  name: string;
  transport: McpTransport;
  endpoint: string;
  shadow: boolean;
  plaintextCredential: boolean;
  owner: string;
  department: string;
  online: boolean;
  riskScore: number;
  firstSeenDays: number;
  lastSeenMinutes: number;
}

const mcpSeeds: McpSeed[] = [
  {
    id: 'mcp-order',
    assetId: ASSET_ID.mcpOrder,
    name: 'order-mcp',
    transport: 'sse',
    endpoint: 'http://order-mcp.intra.acme:8710/sse',
    shadow: false,
    plaintextCredential: false,
    owner: '客户运营部',
    department: '客户运营部',
    online: true,
    riskScore: 74,
    firstSeenDays: 150,
    lastSeenMinutes: 1,
  },
  {
    id: 'mcp-postgres',
    assetId: ASSET_ID.mcpPostgres,
    name: 'postgres-mcp',
    transport: 'stdio',
    endpoint: 'stdio://postgres-mcp --dsn=postgres://readonly@dw.intra.acme:5432/order_db',
    shadow: false,
    plaintextCredential: true,
    owner: '数据平台部',
    department: '数据平台部',
    online: true,
    riskScore: 88,
    firstSeenDays: 140,
    lastSeenMinutes: 2,
  },
  {
    id: 'mcp-fs',
    assetId: ASSET_ID.mcpFs,
    name: 'fs-mcp',
    transport: 'stdio',
    endpoint: 'stdio://fs-mcp --root=/data --root=/srv',
    shadow: false,
    plaintextCredential: false,
    owner: '基础架构部',
    department: '基础架构部',
    online: true,
    riskScore: 69,
    firstSeenDays: 132,
    lastSeenMinutes: 4,
  },
  {
    id: 'mcp-shell',
    assetId: ASSET_ID.mcpShell,
    name: 'shell-mcp',
    transport: 'streamable-http',
    endpoint: 'http://47.98.**.***:18080/mcp',
    shadow: true,
    plaintextCredential: true,
    owner: '—',
    department: '基础架构部',
    online: true,
    riskScore: 96,
    firstSeenDays: 28,
    lastSeenMinutes: 1,
  },
  {
    id: 'mcp-jira',
    assetId: ASSET_ID.mcpJira,
    name: 'jira-mcp',
    transport: 'streamable-http',
    endpoint: 'https://jira-mcp.intra.acme/mcp',
    shadow: false,
    plaintextCredential: false,
    owner: '研发效能部',
    department: '研发效能部',
    online: true,
    riskScore: 41,
    firstSeenDays: 110,
    lastSeenMinutes: 12,
  },
  {
    id: 'mcp-search',
    assetId: ASSET_ID.mcpSearch,
    name: 'web-search-mcp',
    transport: 'sse',
    endpoint: 'https://search-mcp.intra.acme/sse',
    shadow: false,
    plaintextCredential: false,
    owner: '智能应用部',
    department: '智能应用部',
    online: false,
    riskScore: 37,
    firstSeenDays: 300,
    lastSeenMinutes: 320,
  },
  {
    id: 'mcp-clickhouse',
    assetId: ASSET_ID.mcpPostgres,
    name: 'clickhouse-mcp',
    transport: 'stdio',
    endpoint: 'stdio://clickhouse-mcp --host=dw.intra.acme',
    shadow: false,
    plaintextCredential: true,
    owner: '数据平台部',
    department: '数据平台部',
    online: true,
    riskScore: 81,
    firstSeenDays: 118,
    lastSeenMinutes: 7,
  },
  {
    id: 'mcp-browser',
    assetId: ASSET_ID.mcpShell,
    name: 'browser-use-mcp',
    transport: 'websocket',
    endpoint: 'ws://browser-mcp.intra.acme:9001/ws',
    shadow: true,
    plaintextCredential: false,
    owner: '—',
    department: '智能应用部',
    online: true,
    riskScore: 87,
    firstSeenDays: 19,
    lastSeenMinutes: 3,
  },
  {
    id: 'mcp-feishu',
    assetId: ASSET_ID.mcpJira,
    name: 'feishu-mcp',
    transport: 'streamable-http',
    endpoint: 'https://feishu-mcp.intra.acme/mcp',
    shadow: false,
    plaintextCredential: false,
    owner: '研发效能部',
    department: '研发效能部',
    online: true,
    riskScore: 44,
    firstSeenDays: 74,
    lastSeenMinutes: 22,
  },
  {
    id: 'mcp-metrics',
    assetId: ASSET_ID.mcpFs,
    name: 'prometheus-mcp',
    transport: 'sse',
    endpoint: 'http://prom-mcp.intra.acme:9097/sse',
    shadow: false,
    plaintextCredential: false,
    owner: '基础架构部',
    department: '基础架构部',
    online: true,
    riskScore: 33,
    firstSeenDays: 205,
    lastSeenMinutes: 5,
  },
];

export const demoMcpServers: McpServer[] = mcpSeeds.map((seed) => ({
  id: seed.id,
  name: seed.name,
  transport: seed.transport,
  endpoint: seed.endpoint,
  toolCount: 0,
  shadow: seed.shadow,
  plaintextCredential: seed.plaintextCredential,
  owner: seed.owner,
  department: seed.department,
  online: seed.online,
  registeredAt: agoDays(seed.firstSeenDays),
  lastSeenAt: agoMinutes(seed.lastSeenMinutes),
  riskScore: seed.riskScore,
}));
