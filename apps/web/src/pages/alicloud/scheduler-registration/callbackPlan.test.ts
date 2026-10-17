import { describe, expect, it } from 'vitest';
import { CALLBACK_KINDS, PreparationError, prepareCallbackPlan } from './callbackPlan';

const tenantId = 'a12bc345-6789-4abc-8def-0123456789ab';
const input = { origin: 'https://scheduler.example.com:9443/', tenantId, appId: '123', kinds: ['archive', 'log-pull'] };

describe('scheduler callback preparation boundary', () => {
  it('prepares only selected real callbacks with separate tenant and application identity', () => {
    const plan = prepareCallbackPlan(input);
    expect(plan.tasks).toEqual([
      { kind: 'log-pull', method: 'POST', url: 'https://scheduler.example.com:9443/api/v1/internal/jobs/log-pull' },
      { kind: 'archive', method: 'POST', url: 'https://scheduler.example.com:9443/api/v1/internal/jobs/archive' },
    ]);
    expect(plan.deployment.AGF_SCHEDULER_TENANT_ID).toBe(tenantId);
    expect(plan.headers.find(header => header.name === 'schedulerx-appId')?.expectedValue).toBe('123');
    expect(plan.tasks.every(task => !task.url.includes(tenantId))).toBe(true);
    expect(plan.status).toBe('preparation_only');
    expect(plan.cloudRegistrationVerified).toBe(false); expect(plan.deploymentVerified).toBe(false);
    expect(plan.requiredSecretReferences.AGF_SCHEDULER_CALLBACK_TOKEN.supplyFromDeploymentSecret).toBe(true);
    expect(plan.headers.find(header => header.name === 'Authorization')?.valueProvided).toBe(false);
    expect(JSON.stringify(plan)).not.toContain('Bearer <');
  });

  it.each([
    'http://scheduler.example.com', 'http://127.0.0.1:9101',
    'https://user:password@scheduler.example.com', 'https://@scheduler.example.com',
    'https://scheduler.example.com/api', 'https://scheduler.example.com/a/..',
    'https://scheduler.example.com/%2e%2e', 'https://scheduler.example.com//',
    'https://scheduler.example.com?', 'https://scheduler.example.com#',
    'https://scheduler.example.com?token=x', 'https://scheduler.example.com/#section',
    'https://scheduler.example.com\\', ' https://scheduler.example.com',
    'https://scheduler.example.com\n', 'https://scheduler.example.com:', 'not-a-url',
  ])('rejects ambiguous or non-HTTPS origins before generating URLs: %s', origin => {
    expect(() => prepareCallbackPlan({ ...input, origin })).toThrow(new PreparationError('origin'));
  });

  it.each(['default', '', '../tenant', 'a12bc345-6789-4abc-8def-0123456789ab/',
    '00000000-0000-0000-0000-000000000000'])('rejects a missing, slug/path or nil tenant identity: %s', tenantId => {
    expect(() => prepareCallbackPlan({ ...input, tenantId })).toThrow(new PreparationError('tenant'));
  });

  it.each(['', 'app/id', 'app?tenant=other', 'Bearer secret', 'a'.repeat(129),
    'app-main', '0', '01', '+1', '-1', '1e2', '9223372036854775808', '9'.repeat(20)])('rejects an ambiguous app identity: %s', appId => {
    expect(() => prepareCallbackPlan({ ...input, appId })).toThrow(new PreparationError('app'));
  });

  it('preserves the actual maximum int64 application ID in deployment and callback headers', () => {
    const appId = '9223372036854775807';
    const plan = prepareCallbackPlan({ ...input, appId });
    expect(plan.deployment.AGF_SCHEDULER_CALLBACK_APP_ID).toBe(appId);
    expect(plan.headers.find(header => header.name === 'schedulerx-appId')?.expectedValue).toBe(appId);
  });

  it.each([
    { kinds: [] }, { kinds: ['report', 'report'] }, { kinds: ['../report'] }, { kinds: ['report-generate'] },
  ])('requires explicit unique supported callback kinds: $kinds', ({ kinds }) => {
    expect(() => prepareCallbackPlan({ ...input, kinds })).toThrow(new PreparationError('kinds'));
  });

  it('supports all six actual public aliases without fabricating cloud job IDs or execution IDs', () => {
    const plan = prepareCallbackPlan({ ...input, kinds: CALLBACK_KINDS });
    expect(plan.tasks).toHaveLength(6);
    expect(plan.tasks.map(task => task.kind)).toEqual(CALLBACK_KINDS);
    expect(plan.headers.find(header => header.name === 'schedulerx-jobId')).not.toHaveProperty('expectedValue');
    expect(plan.headers.find(header => header.name === 'schedulerx-jobExecutionId')).not.toHaveProperty('expectedValue');
  });
});
