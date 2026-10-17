import { callApi } from './transport';
import type { ApplyInput, ConfigurationObservation, ConfigurationOperation, ConfigurationPreview, ConfigurationState, ObserveInput, PreviewInput } from '@/types/apigConfigurationPublication';
const base = '/api/v1/alicloud/apig/configuration-publication';
const unavailable = (): never => { throw new Error('APIG 配置工作流需要后端 / APIG configuration workflow requires the server'); };
const path = (id: string) => `${base}/operations/${encodeURIComponent(id)}`;
const post = <T,>(url: string, body: unknown) => callApi<T>(url, unavailable, { noFallback: true, method: 'POST', body, timeoutMs: 130_000 });
export const apigConfigurationApi = {
  state: (signal?: AbortSignal) => callApi<ConfigurationState>(base, unavailable, { noFallback: true, signal }),
  observe: (body: ObserveInput) => post<ConfigurationObservation>(`${base}/observe`, body),
  preview: (body: PreviewInput) => post<ConfigurationPreview>(`${base}/previews`, body),
  apply: (body: ApplyInput) => post<ConfigurationOperation>(`${base}/operations`, body),
  receipt: (id: string, signal?: AbortSignal) => callApi<ConfigurationOperation>(path(id), unavailable, { noFallback: true, signal }),
  observeOriginal: (id: string, body: ObserveInput) => post<ConfigurationObservation>(`${path(id)}/observe`, body),
  recover: (id: string) => post<ConfigurationOperation>(`${path(id)}/recover`, {}),
  archive: (body: { expected_generation: number; request_ids: string[] }) => post<{ generation: number; archivedCount: number; archivedRequestIds: string[]; unchanged: boolean }>(`${base}/operations/archive`, body),
};
