import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import * as transport from '@/api/transport';
import i18n from '@/locales/i18n';
import type { Tenant } from '@/types/domain';
import { TenantDirectory } from './TenantDirectory';

afterEach(() => vi.restoreAllMocks());

it('sends the displayed tenant version and refreshes after a concurrent change', async () => {
  await i18n.changeLanguage('en-US');
  const request = vi.spyOn(transport, 'callApi').mockRejectedValue(
    new transport.ApiRequestError('stale tenant', 409, 'conflict'),
  );
  const reload = vi.fn();
  const tenant = {
    id: 'tenant-one', slug: 'tenant-one', name: 'Profile brand', version: 3,
    directoryName: 'Tenant one',
    directoryVersion: 7, enabled: true,
  } as Tenant;
  const view = render(<TenantDirectory tenants={[tenant]} reload={reload} />);
  expect(screen.getByText('Tenant one')).toBeInTheDocument();
  expect(screen.queryByText('Profile brand')).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: 'Disable' }));
  fireEvent.click(await screen.findByRole('button', { name: 'OK' }));

  await waitFor(() => expect(request).toHaveBeenCalledWith(
    '/api/v1/tenants/tenant-one', expect.any(Function),
    expect.objectContaining({ method: 'PATCH', body: {
      name: 'Tenant one', enabled: false, expected_version: 7,
    } }),
  ));
  await waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
  view.unmount();
  await i18n.changeLanguage('zh-CN');
});
