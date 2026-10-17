import { ConfigProvider } from 'antd';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { __resetDataSource } from '@/api/client';
import type { EndpointInput, GatewayEndpoint } from '@/api/gateway';
import i18n from '@/locales/i18n';
import { GatewayConfiguration } from './GatewayConfiguration';

const clients: QueryClient[] = [];
const writes: { method: string; body: EndpointInput }[] = [];
let rows: GatewayEndpoint[] = [];
let respond: (body: EndpointInput) => Response;
const endpoint = (credentialConfigured = false): GatewayEndpoint => ({
  id: 'endpoint-one', version: 4, name: 'Saved endpoint', provider: 'openai', model: 'saved-model',
  baseUrl: 'https://provider.example/v1', localDeployment: false, maxDataClass: 'internal', enabled: true,
  credentialConfigured, mocked: !credentialConfigured,
  pricing: { promptMicroPer1k: 1200000, completionMicroPer1k: 2300000, cachedPromptMicroPer1k: 400000 },
});
beforeEach(async () => {
  __resetDataSource(); await i18n.changeLanguage('en-US'); rows = []; writes.length = 0;
  respond = () => Response.json(endpoint());
  vi.stubGlobal('fetch', vi.fn(async (url: string, options?: RequestInit) => {
    const method = options?.method ?? 'GET';
    if (method === 'POST' || method === 'PUT') {
      const body = JSON.parse(String(options?.body)) as EndpointInput;
      writes.push({ method, body }); return respond(body);
    }
    if (url.endsWith('/gateway/providers')) return Response.json({ items: [
      { value: 'mock', suggestedBaseUrl: 'http://mock.invalid/v1', requiresCustomBaseUrl: false, localDeployment: true },
      { value: 'openai', suggestedBaseUrl: 'https://api.openai.com/v1', requiresCustomBaseUrl: false, localDeployment: false },
      { value: 'bedrock', suggestedBaseUrl: '', requiresCustomBaseUrl: true, localDeployment: false },
      { value: 'deepseek', suggestedBaseUrl: 'https://api.deepseek.com/v1', requiresCustomBaseUrl: false, localDeployment: false },
    ] });
    if (url.endsWith('/gateway/endpoints')) return Response.json({ items: rows });
    throw new Error('Unexpected request: ' + url);
  }));
});
afterEach(async () => {
  cleanup(); clients.splice(0).forEach(client => client.clear()); vi.unstubAllGlobals();
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } }); clients.push(client);
  return render(<MemoryRouter><QueryClientProvider client={client}>
    <ConfigProvider theme={{ token: { motion: false } }}><GatewayConfiguration canWrite /></ConfigProvider>
  </QueryClientProvider></MemoryRouter>);
}
async function choose(provider: string) {
  const select = screen.getByRole('combobox', { name: 'Provider protocol' });
  await waitFor(() => expect(select).not.toBeDisabled()); fireEvent.mouseDown(select);
  fireEvent.click((await screen.findAllByText(provider)).at(-1)!);
}
function fill(name: string, value: string) { fireEvent.change(screen.getByLabelText(name), { target: { value } }); }
function save() { fireEvent.click(screen.getByRole('button', { name: 'Save' })); }
async function create(provider = 'openai') {
  fireEvent.click(await screen.findByRole('button', { name: 'Add endpoint' }));
  await choose(provider); fill('Name', 'No-key endpoint'); fill('Provider model ID', 'actual-model');
  fill('Provider Base URL', 'https://provider.example/v1');
}

it('creates a configured cloud endpoint without a key and shows its returned Mock status without a test call', async () => {
  respond = body => {
    rows = [{ ...endpoint(), name: body.name, model: body.model, baseUrl: body.base_url }];
    return Response.json(rows[0], { status: 201 });
  };
  mount(); await create();
  expect(screen.getByText('Endpoints without saved upstream credentials use local Mock, with zero upstream requests')).toBeInTheDocument();
  expect(screen.getByText(/Controlled private-network Ollama\/vLLM deployments are an exception/)).toBeInTheDocument();
  expect(screen.getByLabelText('Provider credential')).toHaveValue(''); save();
  await screen.findByText('No-key endpoint');
  expect(writes).toHaveLength(1); expect(writes[0].method).toBe('POST');
  expect(writes[0].body).toMatchObject({ expected_version: 0, provider: 'openai', model: 'actual-model',
    base_url: 'https://provider.example/v1', local_deployment: false, enabled: true, max_data_class: 'internal',
    pricing: { prompt_micro_per_1k: 0, completion_micro_per_1k: 0, cached_prompt_micro_per_1k: 0 } });
  expect(writes[0].body).not.toHaveProperty('api_key'); expect(screen.getByText('Mock')).toBeInTheDocument();
  expect(vi.mocked(fetch).mock.calls.every(([url]) => String(url).includes('/gateway/'))).toBe(true);
});
it('edits an uncredentialed endpoint without inventing a key and retains its revision, pricing and classification', async () => {
  rows = [endpoint()]; mount(); fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
  fill('Name', 'Changed no-key endpoint'); fill('Provider Base URL', 'https://changed.example/v1'); save();
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0]).toMatchObject({ method: 'PUT', body: { expected_version: 4, provider: 'openai', model: 'saved-model',
    name: 'Changed no-key endpoint', base_url: 'https://changed.example/v1', local_deployment: false,
    enabled: true, max_data_class: 'internal',
    pricing: { prompt_micro_per_1k: 1200000, completion_micro_per_1k: 2300000, cached_prompt_micro_per_1k: 400000 } } });
  expect(writes[0].body).not.toHaveProperty('api_key');
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument());
});
it.each([
  ['openai', '   ', 'API Key cannot contain only whitespace'],
  ['bedrock', '{}', 'Bedrock credential is missing access_key_id'],
])('retains an explicit invalid %s credential and the server validation error', async (provider, credential, detail) => {
  respond = () => Response.json({ detail }, { status: 400 }); mount(); await create(provider);
  fill('Provider credential', credential); save(); await screen.findByText(new RegExp(detail));
  expect(writes).toHaveLength(1); expect(writes[0].body.api_key).toBe(credential);
  expect(screen.getByLabelText('Provider credential')).toHaveValue(credential);
  expect(screen.getByLabelText('Name')).toHaveValue('No-key endpoint');
  expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled();
});
it.each(['URL', 'provider'])('keeps the server re-entry constraint and draft when an existing keyed endpoint changes %s', async change => {
  rows = [endpoint(true)]; respond = () => Response.json({ detail: 'Re-enter credential for the changed target' }, { status: 400 });
  mount(); fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
  if (change === 'URL') fill('Provider Base URL', 'https://changed.example/v1');
  else { await choose('deepseek'); fill('Provider model ID', 'changed-model'); }
  save(); await screen.findByText(/Re-enter credential for the changed target/);
  expect(writes).toHaveLength(1); expect(writes[0].body.expected_version).toBe(4);
  expect(writes[0].body).not.toHaveProperty('api_key');
  expect(screen.getByLabelText('Provider Base URL')).toHaveValue(writes[0].body.base_url);
  respond = () => Response.json(endpoint(true)); fill('Provider credential', 'synthetic-replacement-key'); save();
  await waitFor(() => expect(writes).toHaveLength(2));
  expect(writes[1].body).toMatchObject({ ...writes[0].body, api_key: 'synthetic-replacement-key', expected_version: 4 });
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument());
});
