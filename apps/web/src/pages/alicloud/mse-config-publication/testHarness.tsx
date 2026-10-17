import { ConfigProvider } from 'antd';
import { act, cleanup, render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, vi } from 'vitest';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import type { Tenant } from '@/types/domain';
import i18n from '@/locales/i18n';
import type { ReactNode } from 'react';
import { publicationApi } from './api';
import { policy, result, state } from './testFixtures';

export const rights = new Set<string>();
const original = useAuthStore.getState(), caches: QueryClient[] = [];
export function installHarness() {
  beforeEach(async () => {
    await i18n.changeLanguage('en-US');
    useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 1 });
    rights.clear(); ['alicloud:read', 'alicloud:write', 'policies:read'].forEach(value => rights.add(value));
    vi.mocked(useSessionAccess).mockImplementation(() => ({ has: (permission: string) => rights.has(permission), isLoading: false }) as ReturnType<typeof useSessionAccess>);
    vi.spyOn(publicationApi, 'state').mockResolvedValue(result(state()));
    vi.spyOn(publicationApi, 'policies').mockResolvedValue(result({ items: [policy()], total: 1, page: 1, pageSize: 50 }));
    window.history.replaceState({}, '', '/');
  });
  afterEach(async () => {
    cleanup(); caches.forEach(cache => cache.clear()); caches.length = 0; vi.restoreAllMocks();
    useAuthStore.setState(original); window.history.replaceState({}, '', '/');
    await act(async () => { await i18n.changeLanguage('zh-CN'); });
  });
}
export function mount(node: ReactNode) {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } }); caches.push(cache);
  const Wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={cache}>
    <ConfigProvider theme={{ token: { motion: false } }}>{children}</ConfigProvider></QueryClientProvider>;
  return render(node, { wrapper: Wrapper });
}
