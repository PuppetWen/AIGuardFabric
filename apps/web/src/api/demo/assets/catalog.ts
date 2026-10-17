import type {
  Asset,
  AssetKind,
  DataClassification,
  DiscoverySource,
  ExposureSurface,
  LifecycleState,
} from '@/types/domain';

import { agoDays, agoMinutes, seeded } from '../../../utils/time';

import type { AssetSeed } from './seeds';
import { assetSeeds, demoDepartments } from './seeds';

/** Synthetic long tail so filters and pagination have something to chew on. */
const generatedKinds: AssetKind[] = ['agent', 'mcp', 'skill', 'model', 'tool'];
const generatedTags = ['batch', 'internal-tool', 'poc', 'legacy', 'data-sync'];

function buildGeneratedAssets(): AssetSeed[] {
  const rand = seeded(20250318);
  const seeds: AssetSeed[] = [];
  for (let i = 0; i < 14; i += 1) {
    const kind = generatedKinds[i % generatedKinds.length] as AssetKind;
    const department = demoDepartments[i % demoDepartments.length] as string;
    const classification = (['public', 'internal', 'confidential', 'restricted'] as DataClassification[])[
      i % 4
    ] as DataClassification;
    const exposure = (
      ['public-internet', 'partner', 'intranet', 'isolated'] as ExposureSurface[]
    )[i % 4] as ExposureSurface;
    seeds.push({
      id: `ast-gen-${String(i + 1).padStart(4, '0')}`,
      name: `${department.replace('部', '')}-${kind}-${String(i + 1).padStart(2, '0')}`,
      kind,
      owner: ['张伟', '刘燕', '陈昊', '王萌', '孙琪'][i % 5] as string,
      department,
      classification,
      lifecycle: (['active', 'active', 'deprecated', 'onboarding', 'planned'] as LifecycleState[])[
        i % 5
      ] as LifecycleState,
      exposure,
      riskScore: Math.round(18 + rand() * 78),
      openFindings: Math.floor(rand() * 4),
      sources: [
        (['agent-scan', 'ingest-log', 'gateway-mirror', 'manual', 'cloud-api'] as DiscoverySource[])[
          i % 5
        ] as DiscoverySource,
      ],
      tags: [generatedTags[i % generatedTags.length] as string, kind],
      description: `由 ${department} 维护的${kind}资产，处于${
        ['试点', '推广', '稳定运行', '维护', '下线'][i % 5] as string
      }阶段。`,
      firstSeenDays: 20 + Math.floor(rand() * 260),
      lastSeenMinutes: 5 + Math.floor(rand() * 2880),
    });
  }
  return seeds;
}

function toAsset(seed: AssetSeed, tenantId: string): Asset {
  return {
    id: seed.id,
    tenantId,
    name: seed.name,
    kind: seed.kind,
    owner: seed.owner,
    department: seed.department,
    classification: seed.classification,
    lifecycle: seed.lifecycle,
    exposure: seed.exposure,
    riskScore: seed.riskScore,
    openFindings: seed.openFindings,
    sources: seed.sources,
    tags: seed.tags,
    firstSeenAt: agoDays(seed.firstSeenDays),
    lastSeenAt: agoMinutes(seed.lastSeenMinutes),
    description: seed.description,
  };
}

const allSeeds: AssetSeed[] = [...assetSeeds, ...buildGeneratedAssets()];

export const demoAssets: Asset[] = allSeeds.map((seed) => toAsset(seed, 'ten-acme'));

export const demoAssetById = new Map<string, Asset>(demoAssets.map((asset) => [asset.id, asset]));

/** Well-known asset ids used by findings, alerts, cases and the topology. */
export const ASSET_ID = {
  agentCopilot: 'ast-agent-0001',
  agentRisk: 'ast-agent-0002',
  agentCodeReview: 'ast-agent-0003',
  agentMarketing: 'ast-agent-0004',
  agentHr: 'ast-agent-0005',
  agentOpsShadow: 'ast-agent-0006',
  mcpOrder: 'ast-mcp-0001',
  mcpPostgres: 'ast-mcp-0002',
  mcpFs: 'ast-mcp-0003',
  mcpShell: 'ast-mcp-0004',
  mcpJira: 'ast-mcp-0005',
  mcpSearch: 'ast-mcp-0006',
  skillPdf: 'ast-skill-0001',
  skillSql: 'ast-skill-0002',
  modelQwenMax: 'ast-model-0001',
  modelLocal: 'ast-model-0002',
  dsOrder: 'ast-ds-0001',
  dsUserProfile: 'ast-ds-0002',
  dsDocs: 'ast-ds-0003',
  credPg: 'ast-cred-0001',
  credOpenai: 'ast-cred-0002',
  epGateway: 'ast-ep-0001',
  epMcpProxy: 'ast-ep-0002',
} as const;
