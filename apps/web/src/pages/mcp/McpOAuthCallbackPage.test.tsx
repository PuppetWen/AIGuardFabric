import { StrictMode } from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { callApi } from '@/api/transport';
import { I18nextProvider } from 'react-i18next';
import i18n from '@/locales/i18n';
import { MCP_OAUTH_FLOW_KEY } from './McpOAuthPanel';
import McpOAuthCallbackPage from './McpOAuthCallbackPage';

vi.mock('@/api/transport', () => ({ callApi: vi.fn(async () => ({ data: { connected: true } })) }));
afterEach(() => { sessionStorage.clear(); window.history.replaceState(null, '', '/'); vi.clearAllMocks(); });

it('removes the authorization code before exchange and sends the browser binding once', async () => {
  sessionStorage.setItem(MCP_OAUTH_FLOW_KEY, JSON.stringify({
    endpointId: 'endpoint-one', state: 'state-one', binding: 'browser-secret', createdAt: Date.now(),
  }));
  window.history.replaceState(null, '', '/mcp/oauth/callback?code=private-code&state=state-one&iss=https%3A%2F%2Fauth.example');
  render(<I18nextProvider i18n={i18n}><StrictMode><McpOAuthCallbackPage /></StrictMode></I18nextProvider>);
  expect(await screen.findByText(/MCP upstream connected|已连接 MCP 上游/)).toBeVisible();
  expect(window.location.search).toBe('');
  await waitFor(() => expect(callApi).toHaveBeenCalledTimes(1));
  expect(callApi).toHaveBeenCalledWith('/api/v1/mcp/endpoints/endpoint-one/oauth/complete',
    expect.any(Function), expect.objectContaining({ method: 'POST', noFallback: true,
      body: { state: 'state-one', binding: 'browser-secret', code: 'private-code', iss: 'https://auth.example' } }));
  expect(sessionStorage.getItem(MCP_OAUTH_FLOW_KEY)).toBeNull();
});
