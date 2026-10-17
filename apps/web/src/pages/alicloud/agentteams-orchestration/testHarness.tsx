import type { ReactNode } from 'react';
import { ConfigProvider } from 'antd';
import { act, cleanup, render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, vi } from 'vitest';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import { agentteamsOrchestrationApi as api } from '@/api/agentteamsOrchestration';
import { preview, result, state, tenantId } from './testFixtures';
export const rights = new Set<string>();
const original = useAuthStore.getState(), caches: QueryClient[] = [];
export function installHarness() {
  beforeEach(async () => {
    await i18n.changeLanguage('en-US');
    useAuthStore.setState({ tenant: { id: tenantId, slug: 'owned' } as Tenant, sessionGeneration: 1 });
    rights.clear(); ['platform:admin', 'alicloud:read', 'alicloud:write'].forEach(permission => rights.add(permission));
    vi.mocked(useSessionAccess).mockImplementation(() => ({ has: (permission: string) => rights.has(permission), isLoading: false }) as unknown as ReturnType<typeof useSessionAccess>);
    vi.spyOn(api, 'state').mockResolvedValue(result(state()));
    vi.spyOn(api, 'preview').mockImplementation(async (_team, body) => result(preview(body)));
    vi.spyOn(api, 'apply'); vi.spyOn(api, 'receipt');
  });
  afterEach(async () => {
    cleanup(); caches.splice(0).forEach(cache => cache.clear()); vi.restoreAllMocks(); useAuthStore.setState(original);
    await act(async () => { await i18n.changeLanguage('zh-CN'); });
  });
}
export function mount(node: ReactNode) {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } }); caches.push(cache);
  return render(node, { wrapper: ({ children }) => <MemoryRouter><QueryClientProvider client={cache}>
    <ConfigProvider theme={{ token: { motion: false } }}>{children}</ConfigProvider></QueryClientProvider></MemoryRouter> });
}
