import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { message } from 'antd';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiRequestError } from '@/api/client';
import { parsersApi, type ParserPreview } from '@/api/parsers';
import { gatewayApi } from '@/api/gateway';
import i18n from '@/locales/i18n';
import { useAuthStore } from '@/stores/authStore';
import type { Parser, Tenant } from '@/types/domain';
import { ParserEditor } from './ParserEditor';

const originalAuth = useAuthStore.getState();
const caches: QueryClient[] = [];
const parser = { id: 'parser-id', name: 'Template' } as Parser;
const localDefinition = '{"key":"test-parser","name":"Unsaved local draft"}';
const localSample = '{"message":"redacted local sample"}';
function result<T>(data: T) {
  return { data, meta: { source: 'live' as const, elapsedMs: 1, at: Date.now() } };
}
function snapshot(version: number, name = 'Server definition'): ParserPreview {
  return { key: 'test-parser', editable: true, enabled: true, priority: 50, version,
    definitionJson: JSON.stringify({ key: 'test-parser', name, engine: 'json-path', pattern: '$' }),
    sampleRaw: '{"message":"server sample"}', outcome: null, note: '' };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(accept => { resolve = accept; });
  return { promise, resolve };
}
beforeEach(async () => {
  await i18n.changeLanguage('en-US');
  useAuthStore.setState({ tenant: { id: 'tenant-one', slug: 'one' } as Tenant, sessionGeneration: 1 });
  vi.spyOn(parsersApi, 'preview').mockResolvedValue(result(snapshot(1)));
  vi.spyOn(parsersApi, 'history').mockResolvedValue(result({ items: [] }));
  vi.spyOn(gatewayApi, 'list').mockResolvedValue(result({ items: [] }));
});
afterEach(async () => {
  cleanup(); caches.forEach(cache => cache.clear()); caches.length = 0;
  act(() => message.destroy());
  vi.restoreAllMocks(); useAuthStore.setState(originalAuth);
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});
async function mount() {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } }); caches.push(cache);
  const onSaved = vi.fn(); const onClose = vi.fn();
  render(<QueryClientProvider client={cache}><ParserEditor parser={parser} onSaved={onSaved} onClose={onClose} /></QueryClientProvider>);
  await screen.findByText('Current revision v1');
  return { onSaved, onClose };
}
function editDraft() {
  fireEvent.change(screen.getByLabelText('Template definition JSON'), { target: { value: localDefinition } });
  fireEvent.change(screen.getByLabelText('Template validation sample'), { target: { value: localSample } });
  fireEvent.change(screen.getByLabelText('Template priority'), { target: { value: '85' } });
  fireEvent.click(screen.getByRole('switch', { name: 'Enabled' }));
}
function expectDraft() {
  expect(screen.getByLabelText('Template definition JSON')).toHaveValue(localDefinition);
  expect(screen.getByLabelText('Template validation sample')).toHaveValue(localSample);
  expect(screen.getByLabelText('Template priority')).toHaveValue('85');
  expect(screen.getByRole('switch', { name: 'Enabled' })).not.toBeChecked();
}
async function saveDraft() {
  const button = screen.getByRole('button', { name: 'Save new revision' });
  await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button);
}

describe('parser editing conflict recovery', () => {
  it('keeps all input and the original save revision after a conflict and a comparison read', async () => {
    const save = vi.spyOn(parsersApi, 'save').mockRejectedValue(new ApiRequestError('Concurrent parser edit', 409, 'conflict', false));
    const { onSaved, onClose } = await mount(); editDraft(); await saveDraft();
    await screen.findByText('The revision changed. Your draft is unsaved. Load the latest revision to compare.');
    expectDraft(); expect(onSaved).not.toHaveBeenCalled(); expect(onClose).not.toHaveBeenCalled();
    vi.mocked(parsersApi.preview).mockResolvedValue(result(snapshot(3, 'Another editor’s definition')));
    fireEvent.click(screen.getByRole('button', { name: 'Load latest revision to compare' }));
    await screen.findByText('Server snapshot v3');
    expect((screen.getByLabelText('Current draft (copyable)') as HTMLTextAreaElement).value).toContain('Unsaved local draft');
    expect((screen.getByLabelText('Latest server snapshot') as HTMLTextAreaElement).value).toContain('Another editor’s definition');
    expectDraft(); expect(screen.getByText('Current revision v1')).toBeInTheDocument();
    expect(save).toHaveBeenCalledTimes(1);
    await saveDraft(); await screen.findByText('Concurrent parser edit');
    expect(save).toHaveBeenLastCalledWith('parser-id', expect.objectContaining({ expected_version: 1,
      definition: JSON.parse(localDefinition), sample: localSample, priority: 85, enabled: false }));
    expect(save).toHaveBeenCalledTimes(2); expect(parsersApi.preview).toHaveBeenCalledTimes(2);
  });

  it('only adopts the latest definition, sample and settings after explicit confirmation, then saves that reviewed revision', async () => {
    const save = vi.spyOn(parsersApi, 'save').mockResolvedValue(result({ id: 'parser-id', version: 4, enabled: true }));
    const { onSaved } = await mount(); editDraft();
    const latest = { ...snapshot(3, 'Latest reviewed content'), priority: 12, sampleRaw: '{"message":"latest sample"}' };
    vi.mocked(parsersApi.preview).mockResolvedValue(result(latest));
    fireEvent.click(screen.getByRole('button', { name: 'Load latest revision to compare' }));
    await screen.findByText('Server snapshot v3');
    fireEvent.click(screen.getByRole('button', { name: 'Adopt latest content and edit again' }));
    await screen.findByText('Replace the current draft?'); expectDraft();
    expect(save).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Confirm draft replacement' }));
    await screen.findByText('Current revision v3');
    expect(screen.getByLabelText('Template definition JSON')).toHaveValue(latest.definitionJson);
    expect(screen.getByLabelText('Template validation sample')).toHaveValue(latest.sampleRaw);
    expect(screen.getByLabelText('Template priority')).toHaveValue('12');
    expect(screen.getByRole('switch', { name: 'Enabled' })).toBeChecked();
    expect(save).not.toHaveBeenCalled();
    // Wait for the confirmation overlay to close; only the visible editor can submit.
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save new revision' })).toBeEnabled());
    await saveDraft();
    await waitFor(() => expect(onSaved).toHaveBeenCalledOnce());
    expect(save).toHaveBeenCalledWith('parser-id', { definition: JSON.parse(latest.definitionJson),
      sample: latest.sampleRaw, priority: 12, enabled: true, expected_version: 3 });
  });

  it.each(['organization', 'sign-in'])('clears old drafts and results on %s changes and ignores a late comparison response', async change => {
    const pending = deferred<ReturnType<typeof result<ParserPreview>>>();
    const validate = vi.spyOn(parsersApi, 'validate').mockResolvedValue(result({ matched: true, fields: { message: 'old result' },
      extra: {}, derivedErrors: [], elapsedMicros: 1 }));
    await mount(); editDraft();
    fireEvent.click(screen.getByRole('button', { name: 'Validate template' }));
    await screen.findByText('Sample parsed successfully'); expect(validate).toHaveBeenCalledOnce();
    vi.mocked(parsersApi.preview).mockReturnValueOnce(pending.promise).mockResolvedValue(result(snapshot(7, 'Fresh session definition')));
    fireEvent.click(screen.getByRole('button', { name: 'Load latest revision to compare' }));
    await waitFor(() => expect(parsersApi.preview).toHaveBeenCalledTimes(2));
    act(() => useAuthStore.setState({ sessionGeneration: 2, ...(change === 'organization'
      ? { tenant: { id: 'tenant-two', slug: 'two' } as Tenant } : {}) }));
    await screen.findByText('Current revision v7');
    await act(async () => { pending.resolve(result(snapshot(99, 'Stale private content'))); });
    expect((screen.getByLabelText('Template definition JSON') as HTMLTextAreaElement).value).toContain('Fresh session definition');
    expect(screen.queryByText('Sample parsed successfully')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Current draft (copyable)')).not.toBeInTheDocument();
    expect(screen.queryByText('Server snapshot v99')).not.toBeInTheDocument();
  });

  it('does not report a late save as successful in another sign-in session', async () => {
    const pending = deferred<ReturnType<typeof result<{ id: string; version: number; enabled: boolean }>>>();
    vi.spyOn(parsersApi, 'save').mockReturnValue(pending.promise);
    const { onSaved, onClose } = await mount(); editDraft(); await saveDraft();
    vi.mocked(parsersApi.preview).mockResolvedValue(result(snapshot(7)));
    act(() => useAuthStore.setState({ sessionGeneration: 2 }));
    await screen.findByText('Current revision v7');
    await act(async () => { pending.resolve(result({ id: 'parser-id', version: 2, enabled: false })); });
    expect(onSaved).not.toHaveBeenCalled(); expect(onClose).not.toHaveBeenCalled();
  });

  it('keeps the draft after a rejected sample and after the latest template becomes unavailable', async () => {
    vi.spyOn(parsersApi, 'save').mockRejectedValue(new ApiRequestError('Sample does not match', 400, 'validation', false));
    const { onSaved } = await mount(); editDraft(); await saveDraft();
    await screen.findByText('Sample does not match'); expectDraft();
    vi.mocked(parsersApi.preview).mockRejectedValue(new ApiRequestError('Template no longer exists', 404, 'not_found', false));
    fireEvent.click(screen.getByRole('button', { name: 'Load latest revision to compare' }));
    await screen.findByText('Template no longer exists'); expectDraft();
    expect(screen.getByText('Current revision v1')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create template' })).not.toBeInTheDocument();
    expect(onSaved).not.toHaveBeenCalled();
  });
});
