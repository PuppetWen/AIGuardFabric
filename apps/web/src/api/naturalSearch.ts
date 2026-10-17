import { callApi } from './transport';

export type NaturalResource = 'assets' | 'findings' | 'alerts' | 'cases';
export interface NaturalSearchResult {
  plan: { status: 'query'; resource: NaturalResource; q?: string | null; severity?: string | null; kind?: string | null };
  results: { items: { id: string; name?: string; title?: string }[]; total: number; page: number; pageSize: number };
  mocked: boolean;
  replayed: boolean;
  modelCalled: boolean;
  model?: string | null;
}

export const naturalSearchEndpoints = {
  naturalSearch: (question: string, page = 1, signal?: AbortSignal) => callApi<NaturalSearchResult>(
    '/api/v1/search/natural',
    () => { throw new Error('Connect to the backend to use natural language search.'); },
    { method: 'POST', body: { question, page, page_size: 20 }, signal, noFallback: true, timeoutMs: 30_000 },
  ),
};
