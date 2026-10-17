import type { Observation, Operation, Preview, PublicationState } from './types';

export function matchingObservation(data: PublicationState, observation: Observation | null, now = Date.now()) {
  return !!observation?.usable && !!data.binding
    && observation.target.targetScopeId === data.binding.targetScopeId
    && observation.target.configurationVersion === data.binding.configurationVersion
    && Number.isFinite(Date.parse(observation.observedAt))
    && now < Date.parse(observation.observedAt) + data.limits.observationSeconds * 1000;
}
export function unknownAcknowledgementReady(data: PublicationState, observation: Observation | null, operation: Operation | null, now = Date.now()) {
  if (!data.unresolvedOperationId) return true;
  const lease = operation ? Date.parse(operation.leaseExpiresAt) : NaN;
  return operation?.requestId === data.unresolvedOperationId && operation.completionState === 'complete' && Number.isFinite(lease) && now > lease
    && !!observation && Date.parse(observation.startedAt) > lease && Date.parse(observation.observedAt) > lease;
}
export function applicable(data: PublicationState, preview: Preview | null, attempted: string | null, now = Date.now()) {
  return !!preview && !!data.binding && preview.previewUsable && preview.consumedBy === null && preview.id !== attempted
    && preview.allowedActions.includes('apply') && data.canApply && !data.busy
    && preview.target.targetScopeId === data.binding.targetScopeId
    && preview.target.configurationVersion === data.binding.configurationVersion
    && preview.stateVersion === data.stateVersion && now < Date.parse(preview.expiresAt);
}
export function originalObservable(data: PublicationState | null, operation: Operation) {
  return !!data?.canObserve && !!data.binding && operation.allowedActions.includes('observe')
    && operation.recoveryScopeId === data.binding.targetScopeId
    && operation.recoveryConfigurationVersion === data.binding.configurationVersion;
}
