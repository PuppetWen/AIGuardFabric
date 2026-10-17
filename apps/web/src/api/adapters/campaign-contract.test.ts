import { describe, expect, it } from 'vitest';
import { adaptResponse } from './index';
import { camelizeDeep } from '../contract';

const adapt = (rows: unknown[]) => adaptResponse('/api/v1/redteam/campaigns', camelizeDeep({ items: rows, total: rows.length, page: 1, page_size: 10 }));
describe('campaign execution contract', () => {
  it('preserves explicit unknown success rate for attempted but unevaluated cases', () => {
    expect(adapt([{ state: 'completed', executed_cases: 3, succeeded_cases: 0,
      success_rate: null, evaluated_cases: 0, inconclusive_cases: 2, failed_cases: 1, ci_passed: false }]))
      .toMatchObject({ items: [{ successRate: null, evaluatedCases: 0, inconclusiveCases: 2, failedCases: 1, ciPassed: false }] });
  });
  it('keeps queued results unknown and preserves all backend categories', () => {
    expect(adapt([{ id: 'one', state: 'queued', categories: ['direct-injection', 'rag-poisoning', 'lateral-movement'],
      executed_cases: 0, succeeded_cases: 0, execution_mode: 'simulator', ci_passed: null, severity_threshold: 'critical' }]))
      .toMatchObject({ items: [{ status: 'planned', successRate: null, blocked: null, bypassed: null,
        categories: ['direct-injection', 'rag-poisoning', 'lateral-movement'], executionMode: 'simulator', ciPassed: null, severityThreshold: 'critical' }] });
  });
  it('does not conflate execution completion with a failed CI gate or replace a real zero', () => {
    expect(adapt([{ state: 'completed', executed_cases: 2, succeeded_cases: 2, ci_gate: true, ci_passed: false, blocked: 0, success_rate: 1 }]))
      .toMatchObject({ items: [{ status: 'succeeded', ciGateEnabled: true, ciPassed: false, blocked: 0, successRate: 1 }] });
    expect(adapt([{ state: 'completed', executed_cases: 2, succeeded_cases: 0, ci_gate: true, ci_passed: true, success_rate: 0 }]))
      .toMatchObject({ items: [{ ciPassed: true, successRate: 0 }] });
  });
});
