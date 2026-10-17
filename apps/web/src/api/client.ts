/**
 * AIGuardFabric API client with a built-in offline demo fallback.
 *
 * Every page talks to the console through this module only:
 *
 *   const { data, isLoading } = useApiQuery('assets', () => api.listAssets(query));
 *
 * `request()` first tries the real backend over `/api` (proxied by Vite to
 * `VITE_API_BASE_URL`, default `http://127.0.0.1:8080`). When that fails — no
 * backend running, network error, timeout, 5xx, or a non-JSON body — the call
 * resolves with the deterministic dataset from `./demo` and flips the module into
 * *demo mode*. `DemoModeBanner` subscribes to that flag and renders the
 * "演示数据（后端未连接）" notice.
 *
 * Set `VITE_FORCE_DEMO=true` to skip the network entirely (useful for UI work).
 *
 * The implementation lives in the sibling modules of this folder; everything
 * they expose to callers is re-exported here so that `@/api/client` stays the
 * single public surface.
 */

import { naturalSearchEndpoints } from './naturalSearch';
import { coreEndpoints } from './endpoints';
import { operationsEndpoints } from './operationsEndpoints';

export * from './config';
export { adaptLoginResponse, camelizeDeep } from './contract';
export type { ChangePasswordResponse, RawReplayResponse } from './contract';
export { __resetDataSource, getDataSourceSnapshot, isDemoMode, subscribeDataSource } from './dataSource';
export type { ApiError, ApiResult, DataSource, DataSourceSnapshot, ResponseMeta } from './dataSource';
export { DEMO_CREDENTIALS, demoLogin } from './demoLogin';
export { summariseQuotas } from './derived';
export { paginate } from './pagination';
export { useApiQuery } from './reactQuery';
export type { UseApiQueryOptions } from './reactQuery';
export { ApiRequestError, callApi, probeBackend } from './transport';

/**
 * Endpoint surface. Every method returns `ApiResult<T>` so callers can inspect
 * `meta.source` if they need to react to the fallback themselves.
 */
export const api = { ...coreEndpoints, ...operationsEndpoints, ...naturalSearchEndpoints } as const;
