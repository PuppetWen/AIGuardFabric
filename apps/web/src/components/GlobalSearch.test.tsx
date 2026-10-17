import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { api, type ApiResult } from '@/api/client';
import type { SearchHit } from '@/api/demo';
import type { Tenant } from '@/types/domain';
import { useAuthStore } from '@/stores/authStore';
import i18n from '@/locales/i18n';
import { GlobalSearch } from './GlobalSearch';

vi.mock('@/api/client', () => ({ api: { search: vi.fn() } }));
const search = vi.mocked(api.search);
const result = (label: string, kind: SearchHit['kind'] = 'asset'): ApiResult<SearchHit[]> => ({
  data: [{ id: 'same-id', label, kind, hint: 'hint', to: `/${kind}s?selected=same-id` }],
  meta: { source: 'live', elapsedMs: 1, at: 1 },
});
function deferred() {
  let resolve!: (value: ApiResult<SearchHit[]>) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<ApiResult<SearchHit[]>>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function Location() { const location = useLocation(); return <output data-testid="location">{location.pathname + location.search}</output>; }
function mount() {
  render(<MemoryRouter><GlobalSearch /><Location /></MemoryRouter>);
  const input = screen.getByRole('combobox');
  fireEvent.focus(input);
  return input;
}
beforeEach(async () => { search.mockReset(); await i18n.changeLanguage('en-US'); useAuthStore.setState({ tenant: null }); });
afterEach(() => { cleanup(); });

describe('global search request isolation', () => {
  it('debounces typing and ignores out-of-order results after cancellation', async () => {
    const old = deferred(); const next = deferred();
    search.mockReturnValueOnce(old.promise).mockReturnValueOnce(next.promise);
    const input = mount();
    fireEvent.change(input, { target: { value: 'old' } });
    await waitFor(() => expect(search).toHaveBeenCalledTimes(1));
    const signal = search.mock.calls[0][1];
    fireEvent.change(input, { target: { value: 'n' } });
    fireEvent.change(input, { target: { value: 'new' } });
    expect(signal?.aborted).toBe(true);
    await waitFor(() => expect(search).toHaveBeenCalledTimes(2));
    expect(search.mock.calls[1][0]).toBe('new');
    await act(async () => next.resolve(result('New result')));
    expect(await screen.findByText('New result')).toBeInTheDocument();
    await act(async () => old.resolve(result('Stale result')));
    expect(screen.queryByText('Stale result')).not.toBeInTheDocument();
  });
  it('shows a recoverable error and Enter retries without fake demo hits', async () => {
    search.mockRejectedValueOnce(new Error('network unavailable')).mockResolvedValueOnce(result('Recovered'));
    const input = mount();
    fireEvent.change(input, { target: { value: 'retry' } });
    expect(await screen.findByRole('alert')).toHaveTextContent('Search failed');
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter', keyCode: 13 });
    expect(await screen.findByText('Recovered')).toBeInTheDocument();
    expect(search).toHaveBeenCalledTimes(2);
  });
  it('clears a pending request and result when changing tenant', async () => {
    const pending = deferred(); search.mockReturnValueOnce(pending.promise);
    const input = mount(); fireEvent.change(input, { target: { value: 'private' } });
    await waitFor(() => expect(search).toHaveBeenCalledTimes(1));
    act(() => useAuthStore.setState({ tenant: { id: 'other' } as Tenant }));
    expect(screen.getByRole('combobox')).toHaveValue('');
    expect(search.mock.calls[0][1]?.aborted).toBe(true);
    await act(async () => pending.reject(new Error('old tenant denied')));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
  it('selects the exact object with keyboard navigation and clears the input', async () => {
    search.mockResolvedValue({ ...result('Asset result'), data: [...result('Asset result').data, ...result('Alert result', 'alert').data] });
    const input = mount(); fireEvent.change(input, { target: { value: 'same' } });
    await screen.findByText('Alert result');
    await waitFor(() => expect(input).toHaveAttribute('aria-expanded', 'true'));
    fireEvent.keyDown(input, { key: 'ArrowDown', code: 'ArrowDown', keyCode: 40 });
    await waitFor(() => expect(input.getAttribute('aria-activedescendant')).toMatch(/_0$/));
    fireEvent.keyDown(input, { key: 'ArrowDown', code: 'ArrowDown', keyCode: 40 });
    await waitFor(() => expect(input.getAttribute('aria-activedescendant')).toMatch(/_1$/));
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter', keyCode: 13 });
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/alerts?selected=same-id'));
    expect(input).toHaveValue('');
    expect(search).toHaveBeenCalledTimes(1);
  });
});
