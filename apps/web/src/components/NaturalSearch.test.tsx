import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { api } from '@/api/client';
import type { NaturalSearchResult } from '@/api/naturalSearch';
import i18n from '@/locales/i18n';
import { NaturalSearch } from './NaturalSearch';

vi.mock('@/api/client', () => ({ api: { naturalSearch: vi.fn() } }));
const query = vi.mocked(api.naturalSearch);
const result = (mocked = false) => ({
  data: { plan: { status: 'query', resource: 'alerts', severity: 'high' },
    results: { items: [{ id: 'owned-alert', title: 'Owned alert' }], total: 21, page: 1, pageSize: 20 },
    mocked, replayed: mocked, modelCalled: !mocked } as NaturalSearchResult,
  meta: { source: 'live' as const, elapsedMs: 1, at: 1 },
});
function Location() { const location = useLocation(); return <output data-testid="location">{location.pathname + location.search}</output>; }
function mount() {
  render(<MemoryRouter><NaturalSearch /><Location /></MemoryRouter>);
  fireEvent.click(screen.getByRole('button', { name: 'Ask about your data' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Search question' }), { target: { value: 'Find high alerts' } });
}
beforeEach(async () => { query.mockReset(); await i18n.changeLanguage('en-US'); });
afterEach(cleanup);

it('uses the server plan and pagination, then opens the exact returned alert', async () => {
  query.mockResolvedValueOnce(result()).mockResolvedValueOnce({ ...result(), data: {
    ...result().data, results: { ...result().data.results, page: 2 },
  } });
  mount(); fireEvent.click(screen.getByRole('button', { name: 'Search' }));
  expect(await screen.findByText('Live model query')).toBeInTheDocument();
  expect(query).toHaveBeenCalledWith('Find high alerts', 1, expect.any(AbortSignal));
  fireEvent.change(screen.getByRole('textbox', { name: 'Search question' }), { target: { value: 'Edited question' } });
  fireEvent.click(screen.getByTitle('2'));
  await waitFor(() => expect(query).toHaveBeenLastCalledWith('Find high alerts', 2, expect.any(AbortSignal)));
  fireEvent.click(await screen.findByRole('button', { name: 'Owned alert' }));
  expect(screen.getByTestId('location')).toHaveTextContent('/alerts?alert=owned-alert');
});

it('labels Mock results, clears stale rows on failure and never invents fallback data', async () => {
  query.mockResolvedValueOnce(result(true)).mockRejectedValueOnce(new Error('Planner unavailable'));
  mount(); fireEvent.click(screen.getByRole('button', { name: 'Search' }));
  expect(await screen.findByText('Mock demo query')).toBeInTheDocument();
  fireEvent.click(await screen.findByRole('button', { name: 'Search' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Planner unavailable');
  expect(screen.queryByRole('button', { name: 'Owned alert' })).not.toBeInTheDocument();
});

it('cancels an in-flight request on close and rejects its later result', async () => {
  let resolve!: (value: ReturnType<typeof result>) => void;
  query.mockReturnValueOnce(new Promise(yes => { resolve = yes; }));
  mount(); fireEvent.click(screen.getByRole('button', { name: 'Search' }));
  const signal = query.mock.calls[0][2];
  fireEvent.click(screen.getByRole('button', { name: 'Close' }));
  expect(signal?.aborted).toBe(true);
  await act(async () => resolve(result()));
  fireEvent.click(screen.getByRole('button', { name: 'Ask about your data' }));
  expect(screen.queryByRole('button', { name: 'Owned alert' })).not.toBeInTheDocument();
});
