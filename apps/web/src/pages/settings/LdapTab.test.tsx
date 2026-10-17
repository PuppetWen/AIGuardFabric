import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ssoApi, type LdapSettings } from '@/api/sso';
import { ApiRequestError } from '@/api/transport';
import i18n from '@/locales/i18n';
import { LdapTab } from './LdapTab';

afterEach(() => vi.restoreAllMocks());

const settings: LdapSettings = {
  revision: '5a507920-326f-40d5-b423-f94062acc177', enabled: true,
  name: 'Company AD', credentialConfigured: true, autoProvision: true, defaultRole: 'viewer',
  config: { url: 'ldaps://ad.example.test:636', startTls: false,
    baseDn: 'ou=People,dc=example,dc=test', bindDn: 'cn=reader,dc=example,dc=test',
    userFilter: '(&(objectClass=user)(sAMAccountName={username}))', idAttribute: 'objectGUID',
    emailAttribute: 'mail', nameAttribute: 'displayName', caPem: '' },
};
const response = { data: settings, meta: { source: 'live' as const, elapsedMs: 1, at: 1 } };

it('uses the loaded revision and retains the edited directory on a conflict', async () => {
  await i18n.changeLanguage('zh-CN');
  vi.spyOn(ssoApi, 'ldapSettings').mockResolvedValue(response);
  const save = vi.spyOn(ssoApi, 'saveLdap').mockRejectedValue(new ApiRequestError('directory changed', 409, 'conflict'));
  const view = render(<LdapTab canWrite />);
  const name = await screen.findByLabelText('目录名称');
  await waitFor(() => expect(name).toHaveValue('Company AD'));
  fireEvent.change(name, { target: { value: 'Renamed directory' } });
  fireEvent.click(screen.getByRole('button', { name: '保存目录配置' }));
  await screen.findByText(/directory changed/);
  expect(save).toHaveBeenCalledWith(expect.objectContaining({ name: 'Renamed directory' }), settings.revision);
  expect(name).toHaveValue('Renamed directory');
  expect(screen.getByRole('button', { name: '保存目录配置' })).toBeDisabled();
  view.unmount();
});

it('keeps the directory secret hidden and read-only for a settings reader', async () => {
  await i18n.changeLanguage('en-US');
  vi.spyOn(ssoApi, 'ldapSettings').mockResolvedValue(response);
  const save = vi.spyOn(ssoApi, 'saveLdap');
  const view = render(<LdapTab canWrite={false} />);
  await waitFor(() => expect(screen.getByLabelText('Directory name')).toHaveValue('Company AD'));
  expect(screen.getByLabelText('Service account password')).toHaveValue('');
  expect(screen.getByRole('button', { name: 'Save directory settings' })).toBeDisabled();
  expect(save).not.toHaveBeenCalled();
  view.unmount();
  await i18n.changeLanguage('zh-CN');
});
