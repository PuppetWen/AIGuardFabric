import { callApi } from './transport';
import type { ArchiveInput, ArchiveResult, Binding, BindingInput, ObservationReceipt, ObserveInput, SchedulerState } from '@/pages/alicloud/scheduler-native/types';

const base = '/api/v1/alicloud/schedulerx3/native';
const unavailable = (): never => { throw new Error('Scheduler native operations require the server / Scheduler 原生操作需要服务端'); };
export const schedulerNativeApi = {
  state: (signal?: AbortSignal) => callApi<SchedulerState>(base, unavailable, { noFallback: true, signal }),
  observe: (body: ObserveInput) => callApi<ObservationReceipt>(`${base}/observe`, unavailable,
    { noFallback: true, method: 'POST', body, timeoutMs: 130_000 }),
  receipt: (id: string, page = 1, signal?: AbortSignal, pageSize = 50) => callApi<ObservationReceipt>(`${base}/observations/${encodeURIComponent(id)}`, unavailable,
    { noFallback: true, query: { page, page_size: pageSize }, signal }),
  bind: (body: BindingInput) => callApi<Binding>(`${base}/bindings`, unavailable, { noFallback: true, method: 'PUT', body }),
  archive: (body: ArchiveInput) => callApi<ArchiveResult>(`${base}/observations/archive`, unavailable, { noFallback: true, method: 'POST', body }),
};
