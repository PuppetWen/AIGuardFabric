import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { notificationApi, type ChannelRow } from '@/api/notifications';
import { ApiRequestError } from '@/api/transport';
import i18n from '@/locales/i18n';
import { NotificationsTab } from './NotificationsTab';

vi.mock('./NotificationHistory', () => ({ NotificationHistory: () => null }));
afterEach(() => vi.restoreAllMocks());

it('preserves a conflicting channel draft and blocks another stale save', async () => {
  await i18n.changeLanguage('en-US');
  const row: ChannelRow = { channel: 'webhook', version: 3, target: '', enabled: true,
    configured: true, mocked: true, settingsJson: '{}', secretKeys: ['auth_header_value'], minSeverity: 'low' };
  vi.spyOn(notificationApi, 'list').mockResolvedValue({ data: [row] } as Awaited<ReturnType<typeof notificationApi.list>>);
  const save = vi.spyOn(notificationApi, 'save').mockRejectedValue(new ApiRequestError('stale channel', 409, 'conflict'));
  const view = render(<NotificationsTab />);
  fireEvent.change(await screen.findByLabelText('Full webhook URL'), { target: { value: 'https://new.invalid/hook' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await screen.findByText('stale channel');
  expect(save).toHaveBeenCalledWith(expect.objectContaining({ version: 3, target: 'https://new.invalid/hook' }));
  expect(screen.getByLabelText('Full webhook URL')).toHaveValue('https://new.invalid/hook');
  await waitFor(() => expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled());
  expect(screen.getByRole('button', { name: 'Reload' })).toBeInTheDocument();
  view.unmount();
  await i18n.changeLanguage('zh-CN');
});
