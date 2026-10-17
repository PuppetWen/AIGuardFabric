import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ssoApi, type OidcSettings } from '@/api/sso';
import { ApiRequestError } from '@/api/transport';
import i18n from '@/locales/i18n';
import { IdentityTab } from './IdentityTab';

afterEach(() => vi.restoreAllMocks());

const config: OidcSettings = {
  revision: '5a507920-326f-40d5-b423-f94062acc177', enabled: false,
  name: 'Mock identity', issuer: 'https://id.example.com/realms/company',
  clientId: 'agf-console', clientAuth: 'none', credentialConfigured: false,
  redirectUri: 'https://console.example.com/login/oidc/callback',
  autoProvision: false, defaultRole: 'viewer', emailDomains: [], discovered: false,
};
const response = { data: config, meta: { source: 'live' as const, elapsedMs: 1, at: 1 } };

it('submits the loaded revision and keeps a conflicting sign-in draft', async () => {
  await i18n.changeLanguage('zh-CN');
  vi.spyOn(ssoApi, 'settings').mockResolvedValue(response);
  const save = vi.spyOn(ssoApi, 'save').mockRejectedValue(new ApiRequestError('sign-in changed', 409, 'conflict'));
  const view = render(<IdentityTab canWrite />);
  const name = await screen.findByLabelText('身份服务名称');
  await waitFor(() => expect(name).toHaveValue('Mock identity'));
  fireEvent.change(name, { target: { value: 'My draft' } });
  fireEvent.click(screen.getByRole('button', { name: '保存并验证配置' }));
  await screen.findByText(/sign-in changed/);
  expect(save).toHaveBeenCalledWith(expect.objectContaining({ name: 'My draft' }), config.revision);
  expect(name).toHaveValue('My draft');
  expect(screen.getByRole('button', { name: '保存并验证配置' })).toBeDisabled();
  expect(screen.getByRole('button', { name: '加载最新企业登录配置' })).toBeInTheDocument();
  view.unmount();
});

it('shows enterprise sign-in configuration without saving for a reader', async () => {
  await i18n.changeLanguage('zh-CN');
  vi.spyOn(ssoApi, 'settings').mockResolvedValue(response);
  const save = vi.spyOn(ssoApi, 'save');
  const view = render(<IdentityTab canWrite={false} />);
  await waitFor(() => expect(screen.getByLabelText('身份服务名称')).toHaveValue('Mock identity'));
  expect(screen.getByRole('button', { name: '保存并验证配置' })).toBeDisabled();
  expect(save).not.toHaveBeenCalled();
  view.unmount();
});

it('explains enterprise sign-in setup in English when English is selected', async () => {
  await i18n.changeLanguage('en-US');
  vi.spyOn(ssoApi, 'settings').mockResolvedValue(response);
  const view = render(<IdentityTab canWrite={false} />);
  await waitFor(() => expect(screen.getByLabelText('Identity provider name')).toHaveValue('Mock identity'));
  expect(screen.getByText(/Register a Web client with authorization code and S256 PKCE/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Save and verify configuration' })).toBeDisabled();
  view.unmount();
  await i18n.changeLanguage('zh-CN');
});
