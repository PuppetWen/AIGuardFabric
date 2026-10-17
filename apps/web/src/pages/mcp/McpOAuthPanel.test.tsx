import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { callApi } from '@/api/transport';
import { McpOAuthPanel } from './McpOAuthPanel';

vi.mock('@/api/transport', () => ({ callApi: vi.fn() }));
beforeEach(() => vi.mocked(callApi).mockReset());

it('requires the browser to use the registered callback origin before starting OAuth', async () => {
  vi.mocked(callApi).mockResolvedValue({ data: {
    configuration: {
      revision: 'revision-one', endpointUrl: 'https://mcp.example.com/mcp',
      registration: 'pre_registered',
      issuer: 'https://auth.example.com', resource: 'https://mcp.example.com/mcp',
      clientId: 'client-one', clientAuth: 'none', scope: 'mcp:tools',
      redirectUri: 'https://console.example.com/mcp/oauth/callback', clientSecretConfigured: false,
    },
    status: { connected: false, expiresAt: null, refreshable: false },
  } } as never);

  render(<McpOAuthPanel id="endpoint-one" canWrite staticCredential={false} zh />);
  fireEvent.click(await screen.findByRole('button', { name: '登录上游并授权' }));
  expect(await screen.findByText(/请先通过已登记的 HTTPS 回调地址所在的控制台入口/)).toBeVisible();
  expect(callApi).toHaveBeenCalledTimes(1);
});

it('saves hosted metadata without requiring a pre-registered client ID or secret', async () => {
  vi.mocked(callApi).mockResolvedValue({ data: {
    configuration: null,
    status: { connected: false, expiresAt: null, refreshable: false },
  } } as never);
  render(<McpOAuthPanel id="endpoint-one" canWrite staticCredential={false} zh />);
  fireEvent.mouseDown(await screen.findByRole('combobox', { name: 'OAuth registration' }));
  fireEvent.click(await screen.findByText('托管 Client ID 元数据（推荐）'));
  fireEvent.change(screen.getByRole('textbox', { name: 'OAuth issuer' }),
    { target: { value: 'https://auth.example.com' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'OAuth redirect URI' }),
    { target: { value: 'https://console.example.com/mcp/oauth/callback' } });
  fireEvent.click(screen.getByRole('button', { name: '保存 OAuth 配置' }));
  await waitFor(() => expect(callApi).toHaveBeenCalledWith(
    '/api/v1/mcp/endpoints/endpoint-one/oauth', expect.any(Function), expect.objectContaining({
      method: 'PUT', body: expect.objectContaining({
        registration: 'client_id_metadata', client_id: '', client_auth: 'none', client_secret: null,
      }),
    }),
  ));
});

it('requests dynamic registration without exposing a manual client ID or secret', async () => {
  vi.mocked(callApi).mockResolvedValue({ data: {
    configuration: null,
    status: { connected: false, expiresAt: null, refreshable: false },
  } } as never);
  render(<McpOAuthPanel id="endpoint-one" canWrite staticCredential={false} zh />);
  fireEvent.mouseDown(await screen.findByRole('combobox', { name: 'OAuth registration' }));
  fireEvent.click(await screen.findByText('动态注册（旧版兼容）'));
  fireEvent.change(screen.getByRole('textbox', { name: 'OAuth issuer' }),
    { target: { value: 'https://auth.example.com' } });
  fireEvent.change(screen.getByLabelText('OAuth initial registration token'),
    { target: { value: 'one-time-registration-token' } });
  fireEvent.click(screen.getByRole('button', { name: '保存 OAuth 配置' }));
  await waitFor(() => expect(callApi).toHaveBeenCalledWith(
    '/api/v1/mcp/endpoints/endpoint-one/oauth', expect.any(Function), expect.objectContaining({
      method: 'PUT', body: expect.objectContaining({
        registration: 'dynamic', client_id: '', client_auth: 'none', client_secret: null,
        registration_access_token: 'one-time-registration-token',
      }),
    }),
  ));
});
