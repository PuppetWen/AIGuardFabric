import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ConfigProvider } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { semanticProfileApi } from '@/api/semanticCacheProfile';
import { gatewayApi } from '@/api/gateway';
import { useSessionAccess } from '@/api/sessionAccess';
import { ApiRequestError } from '@/api/transport';
import i18n from '@/locales/i18n';
import { SemanticCacheProfilePanel } from './SemanticCacheProfilePanel';
import { endpoint, embeddingId, profile, result } from './testFixtures';

vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
const rights = new Set<string>();
beforeEach(async () => {
  await i18n.changeLanguage('en-US'); rights.clear(); rights.add('models:read'); rights.add('models:write');
  vi.mocked(useSessionAccess).mockImplementation(() => ({ has: permission => rights.has(permission) }) as ReturnType<typeof useSessionAccess>);
  vi.spyOn(semanticProfileApi, 'read').mockResolvedValue(result(profile()));
  vi.spyOn(gatewayApi, 'list').mockResolvedValue(result({ items: [endpoint(), endpoint(embeddingId, 'mock-embedding')] }));
  vi.spyOn(semanticProfileApi, 'save').mockImplementation(async body => result(profile({ version: body.expected_version + 1,
    enabled: body.enabled, settings: body.settings })));
});
afterEach(async () => { cleanup(); vi.restoreAllMocks(); await act(async () => { await i18n.changeLanguage('zh-CN'); }); });
const mount = () => render(<MemoryRouter><ConfigProvider theme={{ token: { motion: false } }}><SemanticCacheProfilePanel /></ConfigProvider></MemoryRouter>);

it('offers endpoint-based configuration and a connection guide without displaying credential or URL fields', async () => {
  mount(); await screen.findByDisplayValue('chat-r1');
  expect(screen.getByRole('combobox', { name: 'Chat endpoint' })).toBeInTheDocument();
  expect(screen.getByRole('combobox', { name: 'Embedding endpoint' })).toBeInTheDocument();
  expect(screen.queryByLabelText(/credential|Base URL/i)).not.toBeInTheDocument();
  fireEvent.click(screen.getByText('Semantic cache configuration and connection guide'));
  expect(await screen.findByText(/Clients keep the platform/)).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'View platform client connection steps' })).toHaveAttribute('href', '/guide?tab=platforms');
  expect(semanticProfileApi.save).not.toHaveBeenCalled();
});
it('makes configuration visible to a reader while all writes are disabled', async () => {
  rights.delete('models:write'); mount(); await screen.findByDisplayValue('chat-r1');
  expect(screen.getByRole('button', { name: 'Save cache configuration' })).toBeDisabled();
  expect(screen.getByRole('switch', { name: 'Enable semantic cache configuration' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Read current configuration' })).toBeEnabled();
});
it('shows retained draft and unknown-outcome guidance after a lost save response', async () => {
  vi.mocked(semanticProfileApi.save).mockRejectedValue(new ApiRequestError('Lost response', 0, 'network'));
  mount(); await screen.findByDisplayValue('chat-r1');
  fireEvent.change(screen.getByRole('textbox', { name: 'Chat model revision label' }), { target: { value: 'chat-r2' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save cache configuration' }));
  await screen.findByText('The save result is unknown. Read the current configuration; no retry is automatic.');
  expect(screen.getByDisplayValue('chat-r2')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Adopt current configuration' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Save cache configuration' })).toBeDisabled();
  expect(semanticProfileApi.save).toHaveBeenCalledTimes(1);
});
it('does not fetch or offer enabled writes without model read permission', () => {
  rights.clear(); mount();
  expect(screen.getByText('Model read permission is required to view configuration.')).toBeInTheDocument();
  expect(semanticProfileApi.read).not.toHaveBeenCalled(); expect(gatewayApi.list).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Save cache configuration' })).toBeDisabled();
});
