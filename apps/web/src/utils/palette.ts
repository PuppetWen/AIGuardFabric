import type {
  AdapterHealth,
  AssetKind,
  CaseState,
  DataClassification,
  ExposureSurface,
  LifecycleState,
  PolicyAction,
  PolicyLifecycle,
  RiskDomain,
} from '@/types/domain';

/** Human-readable colour for each risk domain (charts, tags, graph nodes). */
export const DOMAIN_HEX: Record<RiskDomain, string> = {
  asset: '#3d8bfd',
  data: '#9b5cf6',
  identity: '#12a594',
  runtime: '#e5484d',
  compliance: '#d9a326',
};

/** Human-readable colour for each topology node type. */
export const TOPOLOGY_NODE_HEX: Record<string, string> = {
  agent: '#3d8bfd',
  mcp: '#12a594',
  tool: '#d9a326',
  datasource: '#9b5cf6',
  model: '#f26b2c',
};

export const HEALTH_HEX: Record<AdapterHealth, string> = {
  healthy: '#3dd68c',
  degraded: '#d9a326',
  unhealthy: '#e5484d',
  unknown: '#6f7683',
};

export const ASSET_KIND_HEX: Record<AssetKind, string> = {
  agent: '#3d8bfd',
  mcp: '#12a594',
  skill: '#29a3a3',
  model: '#f26b2c',
  tool: '#d9a326',
  datasource: '#9b5cf6',
  credential: '#e5484d',
  endpoint: '#6f7683',
};

/** Colour for a data-classification chip. */
export const CLASSIFICATION_HEX: Record<DataClassification, string> = {
  public: '#3dd68c',
  internal: '#3d8bfd',
  confidential: '#d9a326',
  restricted: '#e5484d',
};

/** Colour for a lifecycle chip. */
export const LIFECYCLE_HEX: Record<LifecycleState, string> = {
  planned: '#8b93a1',
  onboarding: '#3d8bfd',
  active: '#3dd68c',
  deprecated: '#d9a326',
  retired: '#6f7683',
};

/** Colour for an exposure-surface chip — wider exposure is redder. */
export const EXPOSURE_HEX: Record<ExposureSurface, string> = {
  unknown: '#8892a4',
  'public-internet': '#e5484d',
  partner: '#f26b2c',
  intranet: '#3d8bfd',
  isolated: '#3dd68c',
};

/** Colour for a policy action chip. */
export const POLICY_ACTION_HEX: Record<PolicyAction, string> = {
  allow: '#3dd68c',
  deny: '#e5484d',
  alert: '#d9a326',
  mask: '#9b5cf6',
  redirect: '#3d8bfd',
  throttle: '#f26b2c',
  quarantine: '#c2185b',
  quota: '#d9a326',
  approval: '#8fbaff',
  'circuit-break': '#ff8b90',
  unknown: '#8892a4',
};

/** Colour for a policy lifecycle chip. */
export const POLICY_LIFECYCLE_HEX: Record<PolicyLifecycle, string> = {
  draft: '#8b93a1',
  'dry-run': '#d9a326',
  enforced: '#3dd68c',
  disabled: '#6f7683',
};

/** Colour for a case-state kanban column. */
export const CASE_STATE_HEX: Record<CaseState, string> = {
  new: '#e5484d',
  triaged: '#f26b2c',
  containing: '#d9a326',
  recovered: '#12a594',
  closed: '#6f7683',
};

/** Ordered case states, matching the kanban column order. */
export const CASE_STATE_ORDER: CaseState[] = [
  'new',
  'triaged',
  'containing',
  'recovered',
  'closed',
];

/** Shared semantic palette used by charts that are not severity driven. */
export const CHART_PALETTE = ['#3d8bfd', '#12a594', '#d9a326', '#9b5cf6', '#f26b2c', '#e5484d'];
