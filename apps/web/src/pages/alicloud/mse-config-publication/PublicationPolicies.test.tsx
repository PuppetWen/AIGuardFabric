import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import PublicationPolicies from './PublicationPolicies';
import { publicationApi } from './api';
import { installHarness, mount } from './testHarness';
import { policy, policyId, result } from './testFixtures';
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: vi.fn() }));
installHarness();

it('does not silently replace a selected revision after a newer actual row is loaded and permits explicit removal', async () => {
  vi.mocked(publicationApi.policies).mockResolvedValue(result({ items: [{ ...policy(), version: 5, enabled: false }], total: 1, page: 1, pageSize: 50 }));
  const select = vi.fn();
  mount(<PublicationPolicies selected={[{ policyId, version: 4 }]} onSelected={select} maximum={20} disabled={false} />);
  const row = await screen.findByRole('row', { name: /Actual signed policy/ });
  expect(screen.getByText('Still selected v4')).toBeInTheDocument(); expect(select).not.toHaveBeenCalled();
  await waitFor(() => expect(within(row).getByRole('checkbox')).toBeEnabled()); fireEvent.click(within(row).getByRole('checkbox'));
  expect(select).toHaveBeenCalledWith([]);
});
it('retains and explicitly removes a selected policy outside the loaded page without inventing current revisions', async () => {
  const old = '20000000-0000-4000-8000-000000000099', select = vi.fn();
  mount(<PublicationPolicies selected={[{ policyId: old, version: 8 }]} onSelected={select} maximum={20} disabled={false} />);
  await screen.findByText('Actual signed policy'); expect(select).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: `Remove selected policy ${old}` }));
  expect(select).toHaveBeenCalledWith([]);
});
