export const CALLBACK_KINDS = [
  'asset-inventory', 'log-pull', 'redteam-cruise', 'rule-hot-reload', 'report', 'archive',
] as const;
export type CallbackKind = typeof CALLBACK_KINDS[number];
export type PreparationErrorCode = 'origin' | 'tenant' | 'app' | 'kinds';

export class PreparationError extends Error {
  constructor(public readonly code: PreparationErrorCode) {
    super(code);
    this.name = 'PreparationError';
  }
}

export interface PreparationInput {
  origin: string;
  tenantId: string;
  appId: string;
  kinds: readonly string[];
}

function callbackOrigin(raw: string): string {
  // Validate before URL normalization: /a/.., backslashes and empty ?/# must not disappear.
  if (!/^https:\/\/[^/?#\\\s%@]+\/?$/.test(raw) || raw.replace(/\/$/, '').endsWith(':')) {
    throw new PreparationError('origin');
  }
  let url: URL;
  try { url = new URL(raw); } catch { throw new PreparationError('origin'); }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password
    || url.search || url.hash || url.pathname !== '/') throw new PreparationError('origin');
  return url.origin;
}

/** Preparation only. This helper has no networking, registration or secret inputs. */
export function prepareCallbackPlan(input: PreparationInput) {
  const origin = callbackOrigin(input.origin);
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(input.tenantId)
    || input.tenantId === '00000000-0000-0000-0000-000000000000') {
    throw new PreparationError('tenant');
  }
  if (!/^[1-9][0-9]{0,18}$/.test(input.appId) || BigInt(input.appId) > 9223372036854775807n) throw new PreparationError('app');
  if (!input.kinds.length || new Set(input.kinds).size !== input.kinds.length
    || input.kinds.some(kind => !CALLBACK_KINDS.some(candidate => candidate === kind))) {
    throw new PreparationError('kinds');
  }
  const kinds = CALLBACK_KINDS.filter(kind => input.kinds.includes(kind));
  return {
    status: 'preparation_only',
    deploymentVerified: false,
    cloudRegistrationVerified: false,
    callbackOrigin: origin,
    deployment: {
      AGF_SCHEDULER_BACKEND: 'schedulerx3',
      AGF_SCHEDULER_TENANT_ID: input.tenantId.toLowerCase(),
      AGF_SCHEDULER_CALLBACK_APP_ID: input.appId,
    },
    requiredSecretReferences: {
      AGF_SCHEDULER_API_KEY: { supplyFromDeploymentSecret: true, identity: 'same-tenant platform service key' },
      AGF_SCHEDULER_CALLBACK_TOKEN: { supplyFromDeploymentSecret: true, minBytes: 32, maxBytes: 256 },
    },
    headers: [
      { name: 'Authorization', valueSource: 'Bearer plus deployment secret AGF_SCHEDULER_CALLBACK_TOKEN', valueProvided: false },
      { name: 'schedulerx-appId', valueSource: 'actual cloud HTTP application', expectedValue: input.appId },
      { name: 'schedulerx-jobId', valueSource: 'actual positive cloud JobId; not supplied by this preparation' },
      { name: 'schedulerx-jobExecutionId', valueSource: 'actual execution ID; retain for redelivery' },
    ],
    optionalPartitionHeaders: {
      names: ['schedulerx-shardingindex', 'schedulerx-shardingtotal'],
      supplyTogether: true, indexStartsAt: 0, minTotal: 1, maxTotal: 256,
      warning: 'Keep the same total for the whole batch; asset-inventory, rule-hot-reload and report require total=1.',
    },
    tasks: kinds.map(kind => ({ kind, method: 'POST',
      url: `${origin}/api/v1/internal/jobs/${encodeURIComponent(kind)}` })),
    remainingChecks: [
      'Set AGF_SERVER_URL to the fixed platform API origin; verify the same-tenant API key, alicloud:read and task permissions.',
      'Observe actual enabled HTTP jobs and explicitly save trusted current native bindings before starting cloud mode.',
      'Configure database access, task flags and deployment directories; restart the scheduler.',
      'Configure the cloud HTTP executor manually and verify real JobId, network/TLS, calendars and dependencies.',
      'Verify callback receipts and business outputs. Preparation does not register, enable or execute jobs.',
    ],
  };
}

export type CallbackPlan = ReturnType<typeof prepareCallbackPlan>;
