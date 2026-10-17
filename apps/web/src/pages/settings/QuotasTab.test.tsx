import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Form } from 'antd';
import { afterEach, expect, it, vi } from 'vitest';
import { settingsApi } from '@/api/settings';
import { ApiRequestError } from '@/api/transport';
import i18n from '@/locales/i18n';
import type { QuotaDefaults, Tenant } from '@/types/domain';
import { QuotasTab } from './QuotasTab';

afterEach(() => vi.restoreAllMocks());

const tenant: Tenant = { id: 'tenant-one', slug: 'tenant-one', name: 'Tenant one', version: 0, plan: 'enterprise',
  region: 'local', createdAt: '2026-09-23T00:00:00Z',
  whiteLabel: { productName: 'AGF', logoText: 'AGF', primaryColor: '#1677ff' },
  quotaDefaults: { version: 3, tenantTokensPerDay: 100, agentTokensPerHour: 0,
    sessionTokensPerTurn: 500, maxConcurrentSessions: 2 } };

it('retains a conflicting quota draft and prevents a stale retry', async () => {
  await i18n.changeLanguage('en-US');
  const save = vi.spyOn(settingsApi, 'saveQuotas').mockRejectedValue(new ApiRequestError('quota changed', 409, 'conflict'));
  function Editor() {
    const [form] = Form.useForm<QuotaDefaults>();
    return <QuotasTab quotaForm={form} tenant={tenant} canWrite reload={vi.fn()} />;
  }
  const view = render(<Editor />);
  const input = screen.getByLabelText('Tenant daily token limit');
  fireEvent.change(input, { target: { value: '250' } });
  fireEvent.click(screen.getByText('Save').closest('button')!);
  await screen.findByText(/quota changed/);
  expect(save).toHaveBeenCalledWith(expect.objectContaining({ tenantTokensPerDay: 250 }), 3);
  expect(input).toHaveValue('250');
  await waitFor(() => expect(screen.getByText('Save').closest('button')).toBeDisabled());
  expect(screen.getByRole('button', { name: 'Load latest quotas' })).toBeInTheDocument();
  view.unmount();
  await i18n.changeLanguage('zh-CN');
});

it('shows limits without allowing a read-only user to submit changes', async () => {
  await i18n.changeLanguage('en-US');
  const save = vi.spyOn(settingsApi, 'saveQuotas');
  function Reader() {
    const [form] = Form.useForm<QuotaDefaults>();
    return <QuotasTab quotaForm={form} tenant={tenant} canWrite={false} reload={vi.fn()} />;
  }
  const view = render(<Reader />);
  expect(screen.getByLabelText('Tenant daily token limit')).toHaveValue('100');
  expect(screen.getByText('Save').closest('button')).toBeDisabled();
  expect(save).not.toHaveBeenCalled();
  view.unmount();
  await i18n.changeLanguage('zh-CN');
});
