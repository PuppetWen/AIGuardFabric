import type {
  Asset,
  AssetFilter,
  AssetProfile,
  DiscoverySource,
  ExposurePenalty,
  ExposureSurface,
} from '@/types/domain';

import { agoDays, seeded } from '../../utils/time';

import { demoAssets } from './assets/catalog';

/* ------------------------------------------------------------------ */
/* Asset profiles (drawer detail)                                      */
/* ------------------------------------------------------------------ */

const EXPOSURE_PENALTIES: Record<ExposureSurface, ExposurePenalty[]> = {
  unknown: [],
  'public-internet': [
    {
      code: 'EXP-001',
      label: '资产可从互联网直接访问',
      points: 25,
      remediation: '收敛至 WAF / API 网关后端，仅保留鉴权后的最小入口。',
    },
    {
      code: 'EXP-002',
      label: '出入网流量未强制经 DLP 探针',
      points: 12,
      remediation: '将出口流量接入 dlp.intra.acme 并将策略切换为 ai-egress-strict。',
    },
    {
      code: 'EXP-004',
      label: 'TLS 证书剩余有效期不足 30 天',
      points: 6,
      remediation: '启用证书自动续期，或更换为统一的网关证书。',
    },
  ],
  partner: [
    {
      code: 'EXP-005',
      label: '合作方账号拥有过宽的数据访问范围',
      points: 14,
      remediation: '按合作方拆分数据视图，避免直接暴露宽表。',
    },
    {
      code: 'EXP-002',
      label: '出入网流量未强制经 DLP 探针',
      points: 12,
      remediation: '将出口流量接入 dlp.intra.acme。',
    },
  ],
  intranet: [
    {
      code: 'EXP-006',
      label: '内网访问未启用 mTLS 双向认证',
      points: 8,
      remediation: '在 MCP 代理上启用 mTLS，并下发短期客户端证书。',
    },
  ],
  isolated: [],
};

function buildSources(asset: Asset): AssetProfile['sources'] {
  const detail: Record<DiscoverySource, string> = {
    'agent-scan': `主动扫描命中 ${asset.kind} 指纹，版本与依赖已归档。`,
    'ingest-log': '从接入日志中识别到该资产的调用记录。',
    'gateway-mirror': 'AI 网关镜像流量中发现该资产的出入网行为。',
    manual: '由资产负责人在控制台人工登记。',
    'cloud-api': '通过阿里云 OpenAPI 同步发现的托管资源。',
  };
  return asset.sources.map((source, index) => ({
    source,
    at: agoDays(Math.max(1, Math.round((index + 1) * 9))),
    detail: detail[source],
  }));
}

function buildProfile(asset: Asset): AssetProfile {
  const rand = seeded(asset.id.length * 7919 + (asset.riskScore ?? 0));
  const upstream = demoAssets
    .filter((candidate) => candidate.kind === 'agent' && candidate.id !== asset.id)
    .slice(0, asset.kind === 'tool' || asset.kind === 'datasource' ? 2 : 1)
    .map((candidate) => ({ id: candidate.id, name: candidate.name, kind: candidate.kind }));
  const downstream = demoAssets
    .filter((candidate) => candidate.kind === 'mcp' && candidate.id !== asset.id)
    .slice(0, 2)
    .map((candidate) => ({ id: candidate.id, name: candidate.name, kind: candidate.kind }));
  const models = demoAssets
    .filter((candidate) => candidate.kind === 'model')
    .slice(0, asset.kind === 'agent' ? 2 : 1)
    .map((candidate) => ({ id: candidate.id, name: candidate.name, kind: candidate.kind }));
  const datasources = demoAssets
    .filter((candidate) => candidate.kind === 'datasource')
    .slice(0, asset.classification === 'restricted' || asset.classification === 'confidential' ? 2 : 1)
    .map((candidate) => ({ id: candidate.id, name: candidate.name, kind: candidate.kind }));

  return {
    asset,
    runtime: {
      invocations24h: Math.round(600 + rand() * 240_000),
      errorRate: Math.round(rand() * 420) / 10_000,
      avgLatencyMs: Math.round(40 + rand() * 2_400),
      distinctCallers: 1 + Math.floor(rand() * 14),
    },
    dependencies: { upstream, downstream, models, datasources },
    exposurePenalties: EXPOSURE_PENALTIES[asset.exposure],
    sources: buildSources(asset),
  };
}

export const demoAssetProfiles: Record<string, AssetProfile> = Object.fromEntries(
  demoAssets.map((asset) => [asset.id, buildProfile(asset)]),
);

/* ------------------------------------------------------------------ */
/* Filtering helper used by the demo API layer and the pages           */
/* ------------------------------------------------------------------ */

export function filterAssets(assets: Asset[], filter: AssetFilter): Asset[] {
  return assets.filter((asset) => {
    if (filter.kinds?.length && !filter.kinds.includes(asset.kind)) {
      return false;
    }
    if (filter.departments?.length && !filter.departments.includes(asset.department)) {
      return false;
    }
    if (filter.classifications?.length && !filter.classifications.includes(asset.classification)) {
      return false;
    }
    if (filter.lifecycles?.length && !filter.lifecycles.includes(asset.lifecycle)) {
      return false;
    }
    if (filter.exposures?.length && !filter.exposures.includes(asset.exposure)) {
      return false;
    }
    if (filter.keyword) {
      const needle = filter.keyword.trim().toLowerCase();
      const haystack = [asset.name, asset.owner, asset.id, ...asset.tags].join(' ').toLowerCase();
      if (!haystack.includes(needle)) {
        return false;
      }
    }
    return true;
  });
}

/* ------------------------------------------------------------------ */
/* Asset seed catalog (split out, re-exported here)                     */
/* ------------------------------------------------------------------ */

export { demoDepartments } from './assets/seeds';
export { demoAssets, demoAssetById, ASSET_ID } from './assets/catalog';
