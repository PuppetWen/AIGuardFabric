import type { ConfigurationObservation, ConfigurationOperation, ConfigurationState } from '@/types/apigConfigurationPublication';
export const safeRevision = (version: number) => Number.isSafeInteger(version) && version >= 0;
export function matching(data: ConfigurationState | null, o: ConfigurationObservation | null): o is ConfigurationObservation {
  return !!data?.binding && !!o && o.usable && data.observation?.id === o.id
    && o.target.targetScopeId === data.binding.targetScopeId && o.target.configurationVersion === data.binding.configurationVersion
    && safeRevision(data.stateVersion) && safeRevision(o.target.configurationVersion);
}
export function unknownReady(data: ConfigurationState, baseline: ConfigurationObservation, original: ConfigurationOperation | null) {
  if (!data.unresolvedOperationId) return true;
  const lease = Date.parse(original?.leaseExpiresAt ?? ''), now = Date.now();
  return original?.requestId === data.unresolvedOperationId && original.completionState === 'complete'
    && Number.isFinite(lease) && lease <= now && Date.parse(baseline.startedAt) > lease && Date.parse(baseline.observedAt) > lease;
}
export function observable(data: ConfigurationState | null, operation: ConfigurationOperation) {
  return !!data?.binding && data.enabled === true && !data.busy && operation.allowedActions.includes('observe')
    && operation.recoveryScopeId === data.binding.targetScopeId
    && operation.recoveryConfigurationVersion === data.binding.configurationVersion;
}
