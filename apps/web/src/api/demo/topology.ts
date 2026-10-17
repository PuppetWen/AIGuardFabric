import type { TopologyEdge, TopologyGraph, TopologyNode } from '@/types/domain';

import { edgeSeeds, nodeSeeds } from './topology/data';

/* ------------------------------------------------------------------ */
/* Agent → MCP → Tool → data source → model lineage graph              */
/* ------------------------------------------------------------------ */

const nodes: TopologyNode[] = nodeSeeds.map((seed) => ({
  id: seed.id,
  label: seed.label,
  type: seed.type,
  riskScore: seed.riskScore,
  shadow: seed.shadow ?? false,
  classification: seed.classification,
  detail: seed.detail,
}));

const edges: TopologyEdge[] = edgeSeeds.map((seed, index) => ({
  id: `e-${String(index + 1).padStart(3, '0')}`,
  source: seed.source,
  target: seed.target,
  kind: seed.kind,
  egress: seed.egress ?? false,
  calls24h: seed.calls24h,
}));

/**
 * Hard-coded 数据外传路径. Each path starts at an agent and ends at an external
 * sink, passing through the tool that carries the data out.
 */
const egressPaths: string[][] = [
  ['n-agent-marketing', 'n-mcp-search', 'n-tool-fetch-url', 'n-ds-docs'],
  ['n-agent-marketing', 'n-mcp-browser', 'n-tool-fill-form', 'n-ds-user'],
  ['n-agent-risk', 'n-mcp-clickhouse', 'n-tool-ch-export', 'n-ds-oss'],
  ['n-agent-copilot', 'n-mcp-feishu', 'n-tool-upload', 'n-ds-feishu'],
  ['n-agent-etl', 'n-mcp-clickhouse', 'n-tool-ch-export', 'n-ds-order'],
  ['n-agent-ops', 'n-mcp-shell', 'n-tool-run-cmd', 'n-ds-host'],
];

export const demoTopology: TopologyGraph = { nodes, edges, egressPaths };

/** Resolve the ids that participate in any egress path (for graph highlighting). */
export function egressNodeIds(graph: TopologyGraph = demoTopology): string[] {
  return Array.from(new Set(graph.egressPaths.flat()));
}

export function egressEdgeIds(graph: TopologyGraph = demoTopology): string[] {
  const pairs = new Set<string>();
  for (const path of graph.egressPaths) {
    for (let i = 0; i < path.length - 1; i += 1) {
      pairs.add(`${path[i]}->${path[i + 1]}`);
    }
  }
  return graph.edges.filter((edge) => pairs.has(`${edge.source}->${edge.target}`)).map((edge) => edge.id);
}

export { nodes as topologyNodes, edges as topologyEdges };
