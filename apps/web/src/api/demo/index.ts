/**
 * Built-in demo dataset for AIGuardFabric.
 *
 * Everything here is deterministic (see `utils/time.ts`) so the console renders
 * identical data on every reload and unit tests stay stable. `src/api/client.ts`
 * is the only module that is supposed to read from here.
 */

import type {
  AdapterHealthBar,
  DashboardKpi,
  DashboardOverview,
  DomainDistribution,
  RecentAlert,
  RiskDomain,
} from '@/types/domain';

import { demoAlerts } from './reports';
import { demoAssetHealth } from './health';
import { demoAssets } from './assets';
import { demoFindings } from './detection';
import { demoModelUsage, demoTenantUsageRecords } from './models';
import { dailySeries } from '../../utils/time';

export * from './assets';
export * from './audit';
export * from './detection';
export * from './health';
export * from './models';
export * from './platform';
export * from './reports';
export * from './runtime';
export * from './security';
export * from './topology';

const DOMAINS: RiskDomain[] = ['asset', 'data', 'identity', 'runtime', 'compliance'];

function buildKpis(): DashboardKpi[] {
  const openAlerts = demoAlerts.filter((alert) => alert.status === 'open').length;
  const criticalFindings = demoFindings.filter(
    (finding) => finding.severity === 'critical' && finding.status !== 'false-positive',
  ).length;
  const tokenSpend =
    Math.round(
      (demoModelUsage.reduce((sum, item) => sum + item.costCny, 0) / 10 +
        demoTenantUsageRecords.length * 0.4) *
        100,
    ) / 100;
  return [
    {
      key: 'assets',
      label: 'assets',
      value: demoAssets.length,
      unit: 'unit.assets',
      delta: 5,
      sparkline: [28, 29, 30, 31, 31, 33, 34, 35, 36, 37, demoAssets.length],
    },
    {
      key: 'openAlerts',
      label: 'openAlerts',
      value: openAlerts,
      unit: 'unit.findings',
      delta: -3,
      sparkline: [18, 17, 19, 16, 15, 14, 15, 13, 12, 11, openAlerts],
    },
    {
      key: 'criticalFindings',
      label: 'criticalFindings',
      value: criticalFindings,
      unit: 'unit.findings',
      delta: 1,
      sparkline: [2, 2, 3, 3, 2, 3, 4, 4, 3, 4, criticalFindings],
    },
    {
      key: 'redteamSuccessRate',
      label: 'redteamSuccessRate',
      value: 18.9,
      unit: 'common.unit.percent',
      delta: -2.4,
      sparkline: [24, 23, 22, 21, 22, 20, 21, 20, 19, 19, 18.9],
    },
    {
      key: 'tokenSpend',
      label: 'tokenSpend',
      value: tokenSpend,
      unit: 'common.unit.usd',
      delta: 6.8,
      sparkline: [820, 910, 1_040, 980, 1_120, 1_260, 1_180, 1_340, 1_420, 1_380, tokenSpend],
    },
  ];
}

function buildDomainDistribution(): DomainDistribution[] {
  return DOMAINS.map((domain) => {
    const assets = demoAssets.filter((asset) => domainOfAsset(asset.kind) === domain);
    const findings = demoFindings.filter((finding) => finding.domain === domain);
    return {
      domain,
      assets: assets.length,
      findings: findings.length,
      critical: findings.filter((finding) => finding.severity === 'critical').length,
    };
  });
}

function domainOfAsset(kind: string): RiskDomain {
  switch (kind) {
    case 'datasource':
      return 'data';
    case 'credential':
      return 'identity';
    case 'model':
    case 'endpoint':
      return 'asset';
    case 'skill':
      return 'compliance';
    default:
      return 'runtime';
  }
}

function buildRecentAlerts(): RecentAlert[] {
  return [...demoAlerts]
    .sort((a, b) => Date.parse(b.lastSeenAt) - Date.parse(a.lastSeenAt))
    .slice(0, 6)
    .map((alert) => ({
      id: alert.id,
      title: alert.title,
      severity: alert.severity,
      domain: alert.domain,
      assetName: alert.assetName,
      occurredAt: alert.lastSeenAt,
      status: alert.status,
    }));
}

function buildAdapterHealth(): AdapterHealthBar[] {
  return demoAssetHealth;
}

/** Risk trend: daily critical + high findings, 30 days. */
const riskTrend = dailySeries(30, 14, 7, 90210, -3.4);

export const demoDashboard: DashboardOverview = {
  kpis: buildKpis(),
  riskTrend,
  domainDistribution: buildDomainDistribution(),
  topRiskAssets: [...demoAssets].sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1)).slice(0, 8),
  recentAlerts: buildRecentAlerts(),
  adapterHealth: buildAdapterHealth(),
};

/** Keyword index backing the top-bar global search. */
export interface SearchHit {
  id: string;
  label: string;
  kind: 'asset' | 'alert' | 'finding' | 'rule' | 'case' | 'mcp' | 'agent' | 'redteam';
  hint: string;
  to: string;
}

export function searchAll(keyword: string, limit = 8): SearchHit[] {
  const needle = keyword.trim().toLowerCase();
  if (!needle) {
    return [];
  }
  const hits: SearchHit[] = [];
  const match = (...fields: (string | undefined)[]): boolean =>
    fields.some((field) => (field ?? '').toLowerCase().includes(needle));

  for (const asset of demoAssets) {
    if (match(asset.name, asset.id, asset.owner, asset.department, ...asset.tags)) {
      hits.push({
        id: asset.id,
        label: asset.name,
        kind: 'asset',
        hint: `${asset.kind} · ${asset.department} · 风险 ${asset.riskScore}`,
        to: '/assets',
      });
    }
  }
  for (const alert of demoAlerts) {
    if (match(alert.title, alert.id, alert.assetName, alert.source)) {
      hits.push({
        id: alert.id,
        label: alert.title,
        kind: 'alert',
        hint: `${alert.severity} · ${alert.assetName}`,
        to: '/alerts',
      });
    }
  }
  for (const finding of demoFindings) {
    if (match(finding.title, finding.id, finding.ruleName, finding.assetName)) {
      hits.push({
        id: finding.id,
        label: finding.title,
        kind: 'finding',
        hint: `${finding.severity} · ${finding.ruleId}`,
        to: '/findings',
      });
    }
  }

  return hits.slice(0, limit);
}
