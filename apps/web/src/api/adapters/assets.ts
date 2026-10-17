import { list, mapped, measurement, object, strings, text, type ApiObject } from './shared';

const KINDS = {
  'mcp-server': 'mcp', 'mcp-client': 'mcp', 'prompt-template': 'skill',
  'model-endpoint': 'model', 'data-source': 'datasource', 'rag-kb': 'datasource',
  'vector-store': 'datasource', 'compute-node': 'endpoint', 'ide-plugin': 'endpoint',
  collector: 'endpoint', other: 'endpoint',
};
const LIFECYCLES = {
  requested: 'planned', 'under-review': 'onboarding', trial: 'onboarding',
  production: 'active', changing: 'active', archived: 'deprecated', rejected: 'retired',
};
const SOURCES = {
  'agent-report': 'agent-scan', 'network-scan': 'agent-scan', 'git-scan': 'agent-scan',
  'passive-traffic': 'gateway-mirror', collector: 'ingest-log', sidecar: 'manual', import: 'manual',
};

function exposure(raw: ApiObject): string {
  if (raw.exposure) return text(raw.exposure);
  const zones: Record<string, string> = {
    public: 'public-internet', dmz: 'partner', isolated: 'isolated',
    endpoint: 'intranet', intranet: 'intranet', private: 'intranet',
  };
  const zone = zones[text(raw.networkZone).trim().toLowerCase()];
  if (zone) return zone;
  return 'unknown';
}

export function asset(raw: ApiObject): ApiObject {
  const attributes = object(raw.attributes);
  return {
    ...raw,
    kind: mapped(raw.kind, KINDS),
    classification: raw.classification ?? raw.dataClass ?? 'unknown',
    lifecycle: mapped(raw.lifecycle, LIFECYCLES),
    exposure: exposure(raw),
    owner: text(raw.owner, '—'),
    department: text(raw.department).trim() || '—',
    riskScore: measurement(raw.riskScore),
    openFindings: measurement(raw.openFindings),
    sources: raw.sources ?? [mapped(raw.discoverySource, SOURCES)],
    tags: strings(raw.tags),
    firstSeenAt: text(raw.firstSeenAt ?? raw.createdAt),
    lastSeenAt: text(raw.lastSeenAt),
    description: text(raw.description ?? attributes.description ?? raw.endpoint),
    edrHostId: text(attributes.edrHostId ?? attributes.edr_host_id),
    scimUserId: text(attributes.scimUserId ?? attributes.scim_user_id),
  };
}

export function assetProfile(raw: ApiObject): ApiObject {
  const source = object(raw.asset);
  const runtime = object(raw.runtime);
  const dependencies = object(raw.dependencies);
  const sourceKind = mapped(source.discoverySource, SOURCES);
  const profileRuntime = Object.keys(runtime).length ? {
    invocations24h: measurement(runtime.invocations24h),
    errorRate: measurement(runtime.errorRate),
    avgLatencyMs: measurement(runtime.avgLatencyMs),
    distinctCallers: measurement(runtime.distinctCallers),
  } : null;
  return {
    ...raw,
    asset: asset(source),
    runtime: profileRuntime,
    dependencies: {
      upstream: list(dependencies.upstream),
      downstream: dependencies.downstream ?? strings(source.dependencies).map((id) => ({ id, name: id })),
      models: list(dependencies.models),
      datasources: list(dependencies.datasources),
    },
    exposurePenalties: list(raw.exposurePenalties),
    sources: raw.sources ?? (sourceKind ? [{
      source: sourceKind,
      at: text(source.lastSeenAt ?? source.createdAt),
      detail: text(source.endpoint ?? source.fingerprint),
    }] : []),
  };
}
