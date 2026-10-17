import { useSearchParams } from 'react-router-dom';
import { callApi, useApiQuery } from '@/api/client';

/** URL-driven detail data stays isolated by tenant/session through useApiQuery. */
export function useDetailLink<T>(parameter: string, endpoint: string) {
  const [params, setParams] = useSearchParams();
  const id = params.get(parameter) ?? '';
  const detail = useApiQuery(`linked-${parameter}`, () => callApi<T>(
    `${endpoint}/${encodeURIComponent(id)}`, () => { throw new Error('Detail unavailable'); }, { noFallback: true },
  ), { key: [id], enabled: Boolean(id) });
  const select = (next: string | null) => setParams(previous => {
    const updated = new URLSearchParams(previous);
    if (next) updated.set(parameter, next); else updated.delete(parameter);
    return updated;
  });
  return { id, detail, select, value: detail.data?.data };
}
