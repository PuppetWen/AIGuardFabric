import type { ListQuery } from '@/types/domain';

const domains: Record<string, string[]> = {
  runtime: ['prompt-attack', 'tool-abuse'], identity: ['credential-leak'], data: ['rag-poison', 'model-data'],
};

/** Keep all selections, translate display groups and use the server's state field. */
export function findingQuery(filter: { severity?: string[]; domain?: string[]; status?: string[] }, query: ListQuery = {}) {
  return { ...query, severity: filter.severity?.join(','), state: filter.status?.join(','),
    domain: filter.domain?.flatMap(value => domains[value] ?? [value]).join(',') };
}
