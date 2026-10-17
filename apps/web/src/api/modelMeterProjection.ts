import { callApi } from './transport';

/** Node health only; these flags contain no tenant amounts or billing authority. */
export interface ModelMeterProjectionStatus {
  scope: 'node'; readOnly: true;
  committedProjectionIncomplete: boolean; committedGroupsMerged: boolean;
  maxUsageRecordsPerTenant: number; maxFactsPerTenant: number; maxWitnessBytesPerTenant: number;
}
export const modelMeterProjectionApi = {
  read: async (signal?: AbortSignal) => {
    const result = await callApi<ModelMeterProjectionStatus>(
      '/api/v1/models/usage/projection-status', () => null as never, { noFallback: true, signal });
    const value = result.data;
    if (value.scope !== 'node' || value.readOnly !== true
      || typeof value.committedProjectionIncomplete !== 'boolean' || typeof value.committedGroupsMerged !== 'boolean'
      || ![value.maxUsageRecordsPerTenant, value.maxFactsPerTenant, value.maxWitnessBytesPerTenant]
        .every(limit => Number.isSafeInteger(limit) && limit >= 0)) {
      throw new Error('Projection coverage status is invalid / 累计投影状态无效');
    }
    return result;
  },
};
