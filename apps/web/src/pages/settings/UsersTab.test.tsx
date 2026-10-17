import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { message } from 'antd';
import { afterEach, expect, it, vi } from 'vitest';
import { settingsApi } from '@/api/settings';
import { ApiRequestError } from '@/api/transport';
import i18n from '@/locales/i18n';
import type { User } from '@/types/domain';
import { UsersTab } from './UsersTab';

afterEach(() => vi.restoreAllMocks());

const user: User = {
  version: 7, id: 'account-one', tenantId: 'default', identityProvider: 'local',
  username: 'analyst', displayName: 'Analyst', email: 'analyst@example.test',
  role: 'analyst', mfaEnabled: true, mustChangePassword: false,
  lastLoginAt: '2026-09-23T12:00:00Z', status: 'active',
};

it('sends the listed account version and reloads the roster after a conflict', async () => {
  await i18n.changeLanguage('en-US');
  const reload = vi.fn();
  const errorMessage = vi.spyOn(message, 'error');
  const update = vi.spyOn(settingsApi, 'updateUser')
    .mockRejectedValue(new ApiRequestError('Account changed; reload', 409, 'conflict'));
  const view = render(<UsersTab loading={false} error={null} users={[user]}
    onUpdated={reload} onAddUser={vi.fn()} />);
  fireEvent.click(screen.getByRole('button', { name: /disable/i }));
  await waitFor(() => expect(update).toHaveBeenCalledWith('account-one', {
    status: 'disabled', expected_version: 7,
  }));
  await waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
  expect(errorMessage).toHaveBeenCalledWith('This account changed. The list has been refreshed; review it before trying again.');
  view.unmount();
  await i18n.changeLanguage('zh-CN');
});
