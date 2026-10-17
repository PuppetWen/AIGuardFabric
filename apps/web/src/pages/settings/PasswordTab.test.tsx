import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Form } from 'antd';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import { settingsApi } from '@/api/settings';
import { ApiRequestError } from '@/api/transport';
import i18n from '@/locales/i18n';
import type { PasswordPolicy } from '@/types/domain';
import { PasswordTab } from './PasswordTab';

afterEach(() => vi.restoreAllMocks());

const policy: PasswordPolicy = {
  version: 3, minLength: 12, maxAgeDays: 90, historySize: 5, lockoutThreshold: 5,
  requireClasses: true, requireUppercase: true, requireLowercase: true,
  requireDigit: true, requireSymbol: true, mfaEnforced: false,
};

it('retains a conflicting password-policy draft across background refreshes', async () => {
  await i18n.changeLanguage('en-US');
  const save = vi.spyOn(settingsApi, 'savePasswordPolicy')
    .mockRejectedValue(new ApiRequestError('policy changed', 409, 'conflict'));
  function Editor({ current }: { current: PasswordPolicy }) {
    const [form] = Form.useForm<PasswordPolicy>();
    return <MemoryRouter><PasswordTab loading={false} error={null} policyForm={form}
      policy={current} canWrite reload={async () => current} /></MemoryRouter>;
  }
  const view = render(<Editor current={policy} />);
  const input = screen.getByLabelText('Minimum length');
  fireEvent.change(input, { target: { value: '16' } });
  fireEvent.click(screen.getByText('Save').closest('button')!);
  await screen.findByText(/policy changed/);
  expect(save).toHaveBeenCalledWith(expect.objectContaining({ minLength: 16 }), 3);
  view.rerender(<Editor current={{ ...policy, minLength: 10, version: 4 }} />);
  expect(input).toHaveValue('16');
  await waitFor(() => expect(screen.getByText('Save').closest('button')).toBeDisabled());
  expect(screen.getByRole('button', { name: 'Load latest password policy' })).toBeInTheDocument();
  view.unmount();
  await i18n.changeLanguage('zh-CN');
});

it('keeps the password policy visible but not editable for a reader', async () => {
  await i18n.changeLanguage('en-US');
  const save = vi.spyOn(settingsApi, 'savePasswordPolicy');
  function Reader() {
    const [form] = Form.useForm<PasswordPolicy>();
    return <MemoryRouter><PasswordTab loading={false} error={null} policyForm={form}
      policy={policy} canWrite={false} reload={async () => policy} /></MemoryRouter>;
  }
  const view = render(<Reader />);
  expect(screen.getByLabelText('Minimum length')).toHaveValue('12');
  expect(screen.getByText('Save').closest('button')).toBeDisabled();
  expect(save).not.toHaveBeenCalled();
  view.unmount();
  await i18n.changeLanguage('zh-CN');
});
