import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { api } from '@/api/client';
import i18n from '@/locales/i18n';
import { useAlertActions } from './useAlertActions';
import { useAuthStore } from '@/stores/authStore';

afterEach(() => vi.restoreAllMocks());
describe('persisted alert actions', () => {
  it('stops unsent batches after the session or tenant changes', async () => {
    let finish!: () => void;
    const gate = new Promise<void>(resolve => { finish = resolve; });
    const update = vi.spyOn(api, 'updateAlertStatus').mockImplementation(async () => {
      await gate; return { data: undefined, meta: { source: 'live', elapsedMs: 1, at: 1 } };
    });
    const refresh = vi.fn(); const select = vi.fn(); const cache = new QueryClient();
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={cache}>{children}</QueryClientProvider>;
    const hook = renderHook(() => useAlertActions(refresh, select), { wrapper });
    let operation!: Promise<void>;
    act(() => { operation = hook.result.current.update(['a', 'b', 'c', 'd', 'e', 'f'], 'resolved'); });
    expect(update).toHaveBeenCalledTimes(5);
    act(() => useAuthStore.setState({ sessionGeneration: useAuthStore.getState().sessionGeneration + 1 }));
    await act(async () => { finish(); await operation; });
    expect(update).toHaveBeenCalledTimes(5); expect(refresh).not.toHaveBeenCalled(); expect(select).not.toHaveBeenCalled();
    hook.unmount(); cache.clear();
  });
  it('sends each update, reports partial failure, and retains failed IDs for retry', async () => {
    await i18n.changeLanguage('en-US');
    const update = vi.spyOn(api, 'updateAlertStatus').mockImplementation(async id => {
      if (id === 'denied') throw new Error('Permission denied');
      return { data: undefined, meta: { source: 'live', elapsedMs: 1, at: 1 } };
    });
    const refresh = vi.fn().mockResolvedValue(undefined); const select = vi.fn();
    const cache = new QueryClient();
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={cache}>{children}</QueryClientProvider>;
    const hook = renderHook(() => useAlertActions(refresh, select), { wrapper });
    await act(async () => hook.result.current.update(['saved', 'denied'], 'resolved'));
    expect(update.mock.calls).toEqual([['saved', 'resolved'], ['denied', 'resolved']]);
    expect(select).toHaveBeenLastCalledWith(['denied']);
    expect(hook.result.current.failures).toEqual(['denied: Error: Permission denied']);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(hook.result.current.busy).toBe(false);
    update.mockResolvedValue({ data: undefined, meta: { source: 'live', elapsedMs: 1, at: 1 } });
    await act(async () => hook.result.current.update(['denied'], 'resolved'));
    await waitFor(() => expect(hook.result.current.failures).toEqual([]));
    expect(select).toHaveBeenLastCalledWith([]);
    hook.unmount(); cache.clear();
  });
  it('does not report a refresh or saved state when every write fails', async () => {
    vi.spyOn(api, 'updateAlertStatus').mockRejectedValue(new Error('Storage unavailable'));
    const refresh = vi.fn(); const select = vi.fn(); const cache = new QueryClient();
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={cache}>{children}</QueryClientProvider>;
    const hook = renderHook(() => useAlertActions(refresh, select), { wrapper });
    await act(async () => hook.result.current.update(['a', 'b'], 'acknowledged'));
    expect(refresh).not.toHaveBeenCalled(); expect(select).toHaveBeenCalledWith(['a', 'b']);
    expect(hook.result.current.failures).toHaveLength(2);
    hook.unmount(); cache.clear();
  });
});
