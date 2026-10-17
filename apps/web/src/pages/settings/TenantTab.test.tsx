import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Form } from 'antd';
import { afterEach, expect, it, vi } from 'vitest';
import { settingsApi } from '@/api/settings';
import { ApiRequestError } from '@/api/transport';
import i18n from '@/locales/i18n';
import type { Tenant } from '@/types/domain';
import { TenantTab } from './TenantTab';

afterEach(() => vi.restoreAllMocks());

const tenant: Tenant = {
  id: 'tenant-one', slug: 'tenant-one', name: 'Tenant one', version: 3,
  plan: 'enterprise', region: 'cn-hangzhou', createdAt: '2026-09-23T00:00:00Z',
  whiteLabel: { productName: 'AGF', logoText: 'AGF', primaryColor: '#1677ff' },
  quotaDefaults: { version: 0, tenantTokensPerDay: 100, agentTokensPerHour: 0,
    sessionTokensPerTurn: 500, maxConcurrentSessions: 2 },
};

it('retains the organization draft after a stale save and background refresh', async () => {
  await i18n.changeLanguage('en-US');
  const save = vi.spyOn(settingsApi, 'saveTenant').mockRejectedValue(new ApiRequestError('profile changed', 409, 'conflict'));
  function Editor({ profile }: { profile: Tenant }) {
    const [form] = Form.useForm<Tenant>();
    return <TenantTab loading={false} error={null} tenantForm={form} tenant={profile}
      canWrite reload={async () => profile} />;
  }
  const view = render(<Editor profile={tenant} />);
  const input = screen.getByLabelText('Tenant name');
  fireEvent.change(input, { target: { value: 'My draft' } });
  fireEvent.click(screen.getByText('Save').closest('button')!);
  await screen.findByText(/profile changed/);
  expect(save).toHaveBeenCalledWith(expect.objectContaining({ name: 'My draft' }), 3);
  view.rerender(<Editor profile={{ ...tenant, name: 'Another admin', version: 4 }} />);
  expect(input).toHaveValue('My draft');
  await waitFor(() => expect(screen.getByText('Save').closest('button')).toBeDisabled());
  expect(screen.getByRole('button', { name: 'Load latest profile' })).toBeInTheDocument();
  view.unmount();
  await i18n.changeLanguage('zh-CN');
});

it('shows the organization profile to a read-only user without a usable save action', async () => {
  await i18n.changeLanguage('en-US');
  const save = vi.spyOn(settingsApi, 'saveTenant');
  function Reader() {
    const [form] = Form.useForm<Tenant>();
    return <TenantTab loading={false} error={null} tenantForm={form} tenant={tenant}
      canWrite={false} reload={async () => tenant} />;
  }
  const view = render(<Reader />);
  expect(screen.getByLabelText('Tenant name')).toHaveValue('Tenant one');
  expect(screen.getByText('Save').closest('button')).toBeDisabled();
  expect(save).not.toHaveBeenCalled();
  view.unmount();
  await i18n.changeLanguage('zh-CN');
});
