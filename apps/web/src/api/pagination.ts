import type { ListQuery, Paged } from '@/types/domain';

/* ------------------------------------------------------------------ */
/* Pagination helper                                                   */
/* ------------------------------------------------------------------ */

export function paginate<T>(items: T[], query: ListQuery = {}): Paged<T> {
  const page = Math.max(1, query.page ?? 1);
  const pageSize = Math.max(1, query.pageSize ?? 10);
  const start = (page - 1) * pageSize;
  return {
    items: items.slice(start, start + pageSize),
    total: items.length,
    page,
    pageSize,
  };
}

export function sortBy<T>(items: T[], key: string | undefined, order: 'asc' | 'desc' = 'desc'): T[] {
  if (!key) {
    return items;
  }
  const factor = order === 'asc' ? 1 : -1;
  return [...items].sort((a, b) => {
    const left = (a as Record<string, unknown>)[key];
    const right = (b as Record<string, unknown>)[key];
    if (typeof left === 'number' && typeof right === 'number') {
      return (left - right) * factor;
    }
    return String(left ?? '').localeCompare(String(right ?? '')) * factor;
  });
}
