import { describe, expect, it } from 'vitest';
import { adaptResponse } from './index';
import { camelizeDeep } from '../contract';
import { policyBody } from '../payloads';
import fixtures from './server-fixtures';
import type { AssetProfile, Finding, Policy } from '@/types/domain';

const adapt = (path: string, value: unknown) => adaptResponse(`/api/v1/${path}`, camelizeDeep(value));

describe('native server resources captured from the seeded API', () => {
  it.each(Object.entries(fixtures))('preserves pagination while adapting %s', (path, fixture) => {
    const result = adapt(path, { items: [fixture], total: 12, page: 2, page_size: 1 });
    expect(result).toMatchObject({ items: [expect.any(Object)], total: 12, page: 2, pageSize: 1 });
  });

  it('opens raw asset profiles without inventing runtime telemetry', () => {
    const result = adapt('assets/asset-id', { asset: fixtures.assets, changes: [] }) as AssetProfile;
    expect(result.asset).toMatchObject({ kind: 'mcp', classification: 'internal', lifecycle: 'active' });
    expect(result.runtime).toBeNull();
    expect(result.dependencies).toMatchObject({ upstream: [], models: [], datasources: [] });
    expect(result.sources[0].source).toBe('agent-scan');
  });

  it('does not infer network location or risk from exposure points, or trust stale finding attributes', () => {
    for (const exposure_score of [0, 40, 90]) {
      const result = adapt('assets/id', { asset: { ...fixtures.assets, network_zone: undefined,
        risk_score: undefined, exposure_score, attributes: { open_findings: 99 } } }) as AssetProfile;
      expect(result.asset).toMatchObject({ exposure: 'unknown', riskScore: null, openFindings: null });
    }
    const known = adapt('assets/id', { asset: { ...fixtures.assets, network_zone: 'public', exposure_score: 0,
      risk_score: 0, open_findings: 0 } }) as AssetProfile;
    expect(known.asset).toMatchObject({ exposure: 'public-internet', riskScore: 0, openFindings: 0 });
  });

  it('supports absent and native LLM verdicts in findings', () => {
    const empty = adapt('findings/finding-id', fixtures.findings) as Finding;
    expect(empty.llmVerdict).toBeNull();
    expect(empty.evidence[0]).toMatchObject({ kind: 'log', label: expect.any(String) });
    const judged = adapt('findings/finding-id', { ...fixtures.findings, llm_verdict: {
      verdict: 'benign', rationale: 'Allowed operation', judged_at: '2026-09-20T10:00:00Z', confidence: 0.8,
    } }) as Finding;
    expect(judged.llmVerdict).toMatchObject({ verdict: 'false-positive', reasoning: 'Allowed operation' });
  });

  it('keeps missing rule counters absent and uses the actual rule key', () => {
    const result = adapt('rules', { items: [fixtures.rules] });
    expect(result).toMatchObject({ items: [{ id: fixtures.rules.key, hitCount24h: null, falsePositiveRate: null }] });
  });

  it('unwraps case events and renders structured event details as text', () => {
    expect(adapt('cases/case-id/timeline', { events: [
      { id: 'event-id', kind: 'created', note: 'Created case', detail: { reason: 'alert' } },
    ] })).toEqual([{ id: 'event-id', kind: 'created', note: 'Created case', title: 'Created case', detail: '{"reason":"alert"}' }]);
  });

  it('keeps investigating and resolved cases visible in the board columns', () => {
    expect(adapt('cases', { items: [
      { id: 'one', state: 'investigating', asset_ids: ['asset'] }, { id: 'two', state: 'resolved' },
    ] })).toMatchObject({ items: [{ state: 'triaged', assetIds: ['asset'] }, { state: 'recovered' }] });
  });

  it('formats audit actors and report recipients without React object children', () => {
    expect(adapt('audit', { items: [fixtures.audit] })).toMatchObject({ items: [{ actor: expect.any(String) }] });
    expect(adapt('reports', { items: [fixtures.reports] })).toMatchObject({ items: [{ recipients: [], status: 'ready' }] });
  });

  it('preserves structured policy conditions and scopes when saving metadata', () => {
    const policy = adapt('policies/id', { policy: fixtures.policies }) as Policy;
    expect(policyBody(policy)).toMatchObject({ language: 'structured', source: fixtures.policies.source,
      structured: fixtures.policies.structured, intercept_points: fixtures.policies.intercept_points,
      scope_agent_ids: [], scope_departments: [], action: 'deny',
    });
  });
});
