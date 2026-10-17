import { ApiRequestError } from '@/api/transport';
import type { MappingInput, MappingIntent } from './types';
import { uuid } from './text';

export interface PendingRoleWrite {
  asset: string;
  body: Readonly<MappingInput>;
  phase: 'in_flight' | 'unknown' | 'committed' | 'rejected';
}
export function captureWrite(asset: string, body: MappingInput): PendingRoleWrite {
  return { asset, body: Object.freeze({ ...body, change: Object.freeze({ ...body.change }) }), phase: 'in_flight' };
}
export function rejectedBeforeCommit(cause: unknown) {
  return cause instanceof ApiRequestError && cause.status >= 400 && cause.status < 500 && cause.status !== 408;
}
/** A malformed HTTP success cannot prove this immutable request committed. */
export function matchingIntent(value: unknown, asset: string, request: string): value is MappingIntent {
  if (!value || typeof value !== 'object') return false;
  const row = value as Partial<MappingIntent>, original = row.original;
  return uuid(asset) && uuid(request) && row.assetId === asset && row.requestId === request
    && row.immutable === true && row.providerCalled === false && !!original && original.assetId === asset
    && Number.isSafeInteger(original.version) && original.version > 0 && original.governed === true
    && ['eligible', 'revoked', 'unverified', 'disabled'].includes(original.eligibility)
    && original.constraint === 'key_scopes_intersection' && original.cloudPermissionGranted === false
    && !!original.proof && uuid(original.proof.platformRoleId);
}
