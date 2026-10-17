import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import type { LogSource } from '@/types/domain';
import { SourceReplay } from './SourceReplay';

afterEach(() => vi.unstubAllGlobals());

it('runs replay only on POST, displays parser counts, and clears stale results for another source', async () => {
  await i18n.changeLanguage('en-US');
  const fetcher = vi.fn(async (_url: string, _options?: RequestInit) => Response.json({
    replayed: 2, newly_parsed: 2, failed: 0, parser_used: { parser_one: 2 },
    raw_logs: [], notes: [],
  }));
  vi.stubGlobal('fetch', fetcher);
  const sources = [{ id: 'source-one', name: 'First' }, { id: 'source-two', name: 'Second' }] as LogSource[];
  const { rerender, unmount } = render(<SourceReplay sources={sources} source="source-one" onSelect={vi.fn()} />);
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Run replay' }));
  expect(await screen.findByText('parser_one: 2')).toBeInTheDocument();
  expect(fetcher.mock.calls[0][0]).toContain('/api/v1/ingest/replay');
  expect(fetcher.mock.calls[0][1]?.method).toBe('POST');
  expect(JSON.parse(String(fetcher.mock.calls[0][1]?.body))).toMatchObject({ source_id: 'source-one' });
  rerender(<SourceReplay sources={sources} source="source-two" onSelect={vi.fn()} />);
  await waitFor(() => expect(screen.queryByText('parser_one: 2')).not.toBeInTheDocument());
  unmount(); await i18n.changeLanguage('zh-CN');
});
