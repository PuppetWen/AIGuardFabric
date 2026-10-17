import type { AssetFilter, ListQuery } from '@/types/domain';

/** Multi-select filters are a single comma-separated value, matching the API list contract. */
export function assetQuery(filter: AssetFilter = {}, query: ListQuery = {}) {
  return {...query, keyword: filter.keyword ?? query.keyword, kinds: filter.kinds?.join(','),
    classifications: filter.classifications?.join(','), lifecycles: filter.lifecycles?.join(','),
    departments: filter.departments?.join(','), exposures: filter.exposures?.join(',')};
}
