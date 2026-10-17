import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import { __resetDataSource } from '@/api/client';
import i18n from '@/locales/i18n';
import { GatewayConfiguration } from './GatewayConfiguration';

afterEach(() => vi.unstubAllGlobals());

it('keeps a stale model draft and submits its original version only once', async () => {
  __resetDataSource();
  await i18n.changeLanguage('en-US');
  const row = { id: 'endpoint-one', version: 4, name: 'Original endpoint', provider: 'mock',
    model: 'agf-mock', baseUrl: 'http://mock.invalid/v1', localDeployment: true,
    maxDataClass: 'internal', enabled: true, credentialConfigured: false, mocked: true,
    pricing: { promptMicroPer1k: 0, completionMicroPer1k: 0, cachedPromptMicroPer1k: 0 } };
  const writes: unknown[] = [];
  vi.stubGlobal('fetch', vi.fn(async (_url: string, options?: RequestInit) => {
    if (options?.method === 'PUT') {
      writes.push(JSON.parse(String(options.body)));
      return Response.json({ detail: 'stale edit' }, { status: 409 });
    }
    return Response.json({ items: [row] });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const view = render(<MemoryRouter><QueryClientProvider client={client}>
    <GatewayConfiguration canWrite />
  </QueryClientProvider></MemoryRouter>);
  fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
  fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'Unsaved endpoint' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await screen.findByText(/stale edit/);
  expect(screen.getByLabelText('Name')).toHaveValue('Unsaved endpoint');
  await waitFor(() => expect(screen.getByText('Save').closest('button')).toBeDisabled());
  expect(writes).toHaveLength(1);
  expect(writes[0]).toEqual(expect.objectContaining({ name: 'Unsaved endpoint', expected_version: 4 }));
  fireEvent.click(screen.getByText('Save').closest('button')!);
  await waitFor(() => expect(writes).toHaveLength(1));
  view.unmount(); client.clear();
  await i18n.changeLanguage('zh-CN');
});

it('fills a provider URL and preserves a URL entered by the user', async () => {
  __resetDataSource();
  await i18n.changeLanguage('en-US');
  vi.stubGlobal('fetch', vi.fn(async (url: string) => Response.json(url.endsWith('/gateway/providers') ? {
    items: [
      { value: 'mock', suggestedBaseUrl: 'http://mock.invalid/v1', requiresCustomBaseUrl: false, localDeployment: true },
      { value: 'openai', suggestedBaseUrl: 'https://api.openai.com/v1', requiresCustomBaseUrl: false, localDeployment: false },
      { value: 'deepseek', suggestedBaseUrl: 'https://api.deepseek.com/v1', requiresCustomBaseUrl: false, localDeployment: false },
    ],
  } : { items: [] })));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const view = render(<MemoryRouter><QueryClientProvider client={client}>
    <GatewayConfiguration canWrite />
  </QueryClientProvider></MemoryRouter>);
  await screen.findByRole('button', { name: 'Add endpoint' });
  fireEvent.click(screen.getByRole('button', { name: 'Add endpoint' }));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Provider protocol' })).not.toBeDisabled());
  fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Provider protocol' }));
  fireEvent.click((await screen.findAllByText('openai')).at(-1)!);
  await waitFor(() => expect(screen.getByRole('textbox', { name: 'Provider Base URL' })).toHaveValue('https://api.openai.com/v1'));
  expect(screen.getByRole('textbox', { name: 'Provider model ID' })).toHaveValue('');
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider model ID' }),
    { target: { value: 'gpt-4o' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider Base URL' }),
    { target: { value: 'https://private.example/v1' } });
  fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Provider protocol' }));
  fireEvent.click((await screen.findAllByText('deepseek')).at(-1)!);
  expect(screen.getByRole('textbox', { name: 'Provider Base URL' })).toHaveValue('https://private.example/v1');
  expect(screen.getByRole('textbox', { name: 'Provider model ID' })).toHaveValue('');
  view.unmount(); client.clear();
  await i18n.changeLanguage('zh-CN');
});

it('resets edited provider details without carrying a credential to another vendor', async () => {
  __resetDataSource();
  await i18n.changeLanguage('en-US');
  const row = { id: 'endpoint-one', version: 2, name: 'OpenAI endpoint', provider: 'openai',
    model: 'gpt-4o', baseUrl: 'https://api.openai.com/v1', localDeployment: false,
    maxDataClass: 'internal', enabled: true, credentialConfigured: true, mocked: false,
    pricing: { promptMicroPer1k: 0, completionMicroPer1k: 0, cachedPromptMicroPer1k: 0 } };
  vi.stubGlobal('fetch', vi.fn(async (url: string) => Response.json(url.endsWith('/gateway/providers') ? {
    items: [
      { value: 'openai', suggestedBaseUrl: 'https://api.openai.com/v1', requiresCustomBaseUrl: false, localDeployment: false },
      { value: 'deepseek', suggestedBaseUrl: 'https://api.deepseek.com/v1', requiresCustomBaseUrl: false, localDeployment: false },
    ],
  } : { items: [row] })));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const view = render(<MemoryRouter><QueryClientProvider client={client}>
    <GatewayConfiguration canWrite />
  </QueryClientProvider></MemoryRouter>);
  fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Provider protocol' })).not.toBeDisabled());
  fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Provider protocol' }));
  fireEvent.click((await screen.findAllByText('deepseek')).at(-1)!);
  await waitFor(() => expect(screen.getByRole('textbox', { name: 'Provider Base URL' })).toHaveValue('https://api.deepseek.com/v1'));
  expect(screen.getByRole('textbox', { name: 'Provider model ID' })).toHaveValue('');
  expect(screen.getByLabelText('Provider credential')).toHaveValue('');
  fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Provider protocol' }));
  fireEvent.click((await screen.findAllByText('openai')).at(-1)!);
  await waitFor(() => expect(screen.getByRole('textbox', { name: 'Provider Base URL' })).toHaveValue(row.baseUrl));
  expect(screen.getByRole('textbox', { name: 'Provider model ID' })).toHaveValue(row.model);
  view.unmount(); client.clear();
  await i18n.changeLanguage('zh-CN');
});
