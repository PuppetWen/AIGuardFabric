import type { ApigObservation, ApigOperation, ApigPreview, ApigPublicationState } from '@/types/apigPolicyPublication';
export function matchingObservation(data: ApigPublicationState, row: ApigObservation | null, now = Date.now()) {
  return !!row?.usable && !!data.binding && data.observation?.id === row.id
    && row.target.targetScopeId === data.binding.targetScopeId && row.target.configurationVersion === data.binding.configurationVersion
    && Number.isFinite(Date.parse(row.observedAt)) && now < Date.parse(row.observedAt) + data.limits.observationSeconds * 1000;
}
export function unknownReady(data: ApigPublicationState, row: ApigObservation | null, operation: ApigOperation | null, now = Date.now()) {
  if (!data.unresolvedOperationId) return true;
  const lease = operation ? Date.parse(operation.leaseExpiresAt) : NaN;
  return operation?.requestId === data.unresolvedOperationId && operation.completionState === 'complete'
    && Number.isFinite(lease) && now > lease && !!row && Date.parse(row.startedAt) > lease && Date.parse(row.observedAt) > lease;
}
export function applicable(data: ApigPublicationState, row: ApigPreview | null, attempted: string | null, now = Date.now()) {
  return !!row && !!data.binding && row.previewUsable && row.consumedBy === null && row.id !== attempted && row.allowedActions.includes('apply')
    && data.canApply && !data.busy && row.target.targetScopeId === data.binding.targetScopeId
    && row.target.configurationVersion === data.binding.configurationVersion && row.stateVersion === data.stateVersion && now < Date.parse(row.expiresAt);
}
export function originalObservable(data: ApigPublicationState | null, row: ApigOperation) {
  return !!data?.canObserve && !!data.binding && row.allowedActions.includes('observe')
    && row.recoveryScopeId === data.binding.targetScopeId && row.recoveryConfigurationVersion === data.binding.configurationVersion;
}
