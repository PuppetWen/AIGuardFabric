import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { parsersApi, type ParserPreview } from '@/api/parsers';
import { gatewayApi } from '@/api/gateway';
import i18n from '@/locales/i18n';
import type { Parser } from '@/types/domain';
import { ParserEditor } from './ParserEditor';

function result<T>(data: T) {
  return { data, meta: { source: 'live' as const, elapsedMs: 1, at: Date.now() } };
}
function snapshot(version: number, name: string): ParserPreview {
  return { key: 'test-parser', editable: true, enabled: true, priority: 50, version,
    definitionJson: JSON.stringify({ key: 'test-parser', name, engine: 'json-path', pattern: '$' }),
    sampleRaw: '{"message":"test"}', outcome: null, note: '' };
}
describe('parser version editor', () => {
  it('loads the current revision every time it opens and does not replace unsaved edits', async () => {
    await i18n.changeLanguage('zh-CN');
    const preview = vi.spyOn(parsersApi, 'preview')
      .mockResolvedValueOnce(result(snapshot(1, 'First')))
      .mockResolvedValueOnce(result(snapshot(3, 'Restored')));
    const history = vi.spyOn(parsersApi, 'history').mockResolvedValue(result({ items: [] }));
    const models = vi.spyOn(gatewayApi, 'list').mockResolvedValue(result({ items: [] }));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 60000 } } });
    const parser = { id: 'parser-id', name: 'Template' } as Parser;
    const tree = (open: boolean) => <QueryClientProvider client={client}>
      {open && <ParserEditor parser={parser} onSaved={() => undefined} onClose={() => undefined} />}
    </QueryClientProvider>;
    const rendered = render(tree(true));
    await screen.findByText('当前版本 v1');
    fireEvent.change(screen.getByLabelText('模板定义 JSON'), { target: { value: '{"name":"Unsaved"}' } });
    rendered.rerender(tree(true));
    expect((screen.getByLabelText('模板定义 JSON') as HTMLTextAreaElement).value).toContain('Unsaved');
    rendered.rerender(tree(false));
    rendered.rerender(tree(true));
    await screen.findByText('当前版本 v3');
    expect((screen.getByLabelText('模板定义 JSON') as HTMLTextAreaElement).value).toContain('Restored');
    expect(preview).toHaveBeenCalledTimes(2);
    rendered.unmount(); client.clear();
    preview.mockRestore(); history.mockRestore(); models.mockRestore();
  });
});
