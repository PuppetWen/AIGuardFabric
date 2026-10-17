import { callApi } from './transport';

export interface ParseOutcome {
  matched: boolean; parserKey?: string; fields: Record<string, unknown>; extra: Record<string, unknown>;
  derivedErrors: string[]; error?: string; elapsedMicros: number;
}
export interface ParserPreview {
  editable: boolean; enabled: boolean; priority: number; version: number;
  key: string; definitionJson: string; sampleRaw: string | null; outcome: ParseOutcome | null; note: string;
}
const unavailable = (): never => { throw new Error('解析器操作需要连接后端'); };
export interface ParserInput {
  definition: Record<string, unknown>; sample: string; priority: number; enabled: boolean; expected_version?: number;
}
interface Saved { id: string; version: number; enabled: boolean }
const options = { noFallback: true, opaqueKeys: ['fields', 'extra'] };
export const parsersApi = {
  suggest: (sample: string, model?: string, data_class = 'restricted') => callApi<{
    definitionJson: string; sample: string; mocked: boolean; note: string;
  }>('/api/v1/parsers/suggest', unavailable, { method: 'POST', body: { sample, model, data_class }, timeoutMs: 120_000, ...options }),
  preview: (id: string) => callApi<ParserPreview>('/api/v1/parsers/' + encodeURIComponent(id) + '/preview', unavailable, options),
  test: (id: string, sample: string) => callApi<ParseOutcome>('/api/v1/parsers/' + encodeURIComponent(id) + '/test', unavailable,
    { method: 'POST', body: { sample }, ...options }),
  validate: (body: ParserInput) => callApi<ParseOutcome>('/api/v1/parsers/validate', unavailable, { method: 'POST', body, ...options }),
  save: (id: string | undefined, body: ParserInput) => callApi<Saved>('/api/v1/parsers' + (id ? '/' + encodeURIComponent(id) : ''),
    unavailable, { method: id ? 'PUT' : 'POST', body, ...options }),
  history: (id: string) => callApi<{items: {version: number; updatedAt: string; enabled: boolean}[]}>(
    '/api/v1/parsers/' + encodeURIComponent(id) + '/history', unavailable, options),
  restore: (id: string, version: number, expected_version: number) => callApi<Saved>('/api/v1/parsers/' + encodeURIComponent(id) + '/restore',
    unavailable, { method: 'POST', body: { version, expected_version }, ...options }),
  delete: (id: string, expected_version: number) => callApi('/api/v1/parsers/' + encodeURIComponent(id), unavailable,
    { method: 'DELETE', body: { expected_version }, ...options }),
};
