import { useEffect, useRef, useState } from 'react';
import { runtimeQuotaConfiguration, type RuntimeQuotaDefinition } from '@/api/runtimeQuotaConfiguration';
import { useOperationScope } from '@/components/receipts/useOperationScope';

const PAGE_SIZE = 100, MAX_PAGES = 20;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function selectableQuota(quota: RuntimeQuotaDefinition) {
  return quota.enabled && uuid.test(quota.id) && quota.id !== '00000000-0000-0000-0000-000000000000'
    && Number.isSafeInteger(quota.version) && quota.version > 0;
}

/** Reads only explicitly loaded pages; no selection changes or unbounded registry scans. */
export function usePolicyQuotaOptions() {
  const scope = useOperationScope(), sequence = useRef(0);
  const [page, setPage] = useState(1), [reload, setReload] = useState(0);
  const [rows, setRows] = useState<RuntimeQuotaDefinition[]>([]), [total, setTotal] = useState<number | null>(null);
  const [loading, setLoading] = useState(true), [error, setError] = useState(''), [complete, setComplete] = useState(false);
  const [hasMore, setHasMore] = useState(false);
  useEffect(() => {
    const id = ++sequence.current, controller = new AbortController();
    if (!scope.current()) return () => controller.abort();
    void runtimeQuotaConfiguration.list(page, '', PAGE_SIZE, controller.signal).then(response => {
      if (controller.signal.aborted || !scope.current() || id !== sequence.current) return;
      const data = response.data;
      if (!Array.isArray(data.items) || data.items.length > PAGE_SIZE || data.page !== page
        || typeof data.hasMore !== 'boolean' || !Number.isSafeInteger(data.total) || data.total < 0) {
        throw new Error('Invalid quota list response / 配额列表响应无效');
      }
      setRows(previous => {
        const merged = new Map((page === 1 ? [] : previous).map(row => [row.id, row]));
        data.items.forEach(entry => merged.set(entry.quota.id, entry.quota));
        return [...merged.values()];
      });
      setTotal(data.total); setComplete(!data.hasMore); setHasMore(data.hasMore); setError('');
    }).catch(cause => {
      if (!controller.signal.aborted && scope.current() && id === sequence.current) {
        setError(cause instanceof Error ? cause.message : String(cause)); setComplete(false);
      }
    }).finally(() => {
      if (!controller.signal.aborted && scope.current() && id === sequence.current) setLoading(false);
    });
    return () => controller.abort();
  }, [page, reload, scope]);
  const refresh = () => {
    if (!scope.current() || loading) return;
    setLoading(true); setError(''); setRows([]); setTotal(null); setComplete(false); setHasMore(false);
    setPage(1); setReload(value => value + 1);
  };
  const loadMore = () => {
    if (!scope.current() || loading || error || !hasMore || page >= MAX_PAGES) return;
    setLoading(true); setComplete(false); setPage(value => value + 1);
  };
  return { rows, total, loading, error, complete, refresh, loadMore,
    canLoadMore: hasMore && page < MAX_PAGES, bounded: hasMore && page >= MAX_PAGES };
}
