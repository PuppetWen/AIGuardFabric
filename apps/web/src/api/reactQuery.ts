import { useQuery, type UseQueryOptions, type UseQueryResult } from '@tanstack/react-query';

import { useAuthStore } from '@/stores/authStore';

import { currentSource, type ApiResult, type DataSource } from './dataSource';
import { sessionChangedError } from './transport';

/* ------------------------------------------------------------------ */
/* React Query integration                                             */
/* ------------------------------------------------------------------ */

export interface UseApiQueryOptions {
  /** React Query key suffix; defaults to the display name + params. */
  key?: readonly unknown[];
  enabled?: boolean;
  refetchInterval?: number | false;
  staleTime?: number;
}

const DEFAULT_STALE_TIME = 15_000;

/**
 * Thin wrapper around `useQuery` that unwraps `ApiResult<T>` and surfaces the
 * data source, so pages do not each have to remember the demo fallback.
 */
export function useApiQuery<T>(
  name: string,
  fetcher: () => Promise<ApiResult<T>>,
  options: UseApiQueryOptions = {},
): UseQueryResult<ApiResult<T>> & { source: DataSource } {
  const tenantId = useAuthStore((state) => state.tenant?.id);
  const tenantSlug = useAuthStore((state) => state.tenant?.slug);
  const sessionKey = useAuthStore((state) => state.sessionGeneration);
  const assertScope = () => {
    const current = useAuthStore.getState();
    if (current.tenant?.id !== tenantId || current.tenant?.slug !== tenantSlug || current.sessionGeneration !== sessionKey) {
      throw sessionChangedError();
    }
  };
  const query = useQuery<ApiResult<T>>({
    queryKey: ['agf', name, tenantId, sessionKey, ...(options.key ?? [])],
    queryFn: async () => {
      // An inactive old query can retry later; never dispatch it using another tenant's identity.
      assertScope();
      try {
        const response = await fetcher();
        assertScope();
        return response;
      } catch (error) {
        assertScope();
        throw error;
      }
    },
    enabled: options.enabled ?? true,
    refetchInterval: options.refetchInterval ?? false,
    staleTime: options.staleTime ?? DEFAULT_STALE_TIME,
  } as UseQueryOptions<ApiResult<T>>);

  return Object.assign(query, { source: query.data?.meta.source ?? currentSource() });
}
