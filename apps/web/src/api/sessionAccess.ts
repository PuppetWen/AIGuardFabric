import { useApiQuery } from './client';
import { callApi } from './transport';
import { FORCE_DEMO } from './config';

interface SessionIdentity { access: Record<string, boolean>; roles: string[]; superadmin: boolean }

/** Every required query on the initial page must be readable. Individual writes remain server-checked. */
export const PAGE_PERMISSIONS: Record<string, string[]> = {
  '/': ['assets:read'], '/assets': ['assets:read'], '/agents': ['agents:read'],
  '/mcps': ['mcps:read'], '/skills': ['skills:read'], '/models': ['models:read'],
  '/topology': ['assets:read'], '/findings': ['findings:read'], '/rules': ['rules:read'],
  '/redteam': ['redteam:read'], '/alerts': ['alerts:read'], '/cases': ['cases:read'],
  '/policies': ['policies:read'], '/runtime': ['policies:read', 'quotas:read', 'settings:read'],
  '/ingest': ['sources:read', 'parsers:read'], '/integrations': ['integrations:read'],
  '/alicloud': ['alicloud:read'], '/audit': ['audit:read'], '/reports': ['reports:read'],
  '/settings': ['settings:read'], '/guide': [], '/security': [],
};

export function useSessionAccess() {
  const query = useApiQuery('session-access', async () => {
    const response = await callApi<SessionIdentity>('/api/v1/auth/me', () => null as never, { noFallback: true });
    if (!response.data.access || typeof response.data.access !== 'object') {
      throw new Error('The server did not return access capabilities / 服务器未返回页面权限，请检查前后端版本');
    }
    return response;
  }, { enabled: !FORCE_DEMO, staleTime: 0, refetchInterval: 30_000 });
  const has = (permission: string) => !query.error && query.data?.data.access[permission] === true;
  const allows = (path: string) => FORCE_DEMO || (PAGE_PERMISSIONS[path] ?? []).every(has);
  return { ...query, has, allows, identity: query.data?.data };
}

