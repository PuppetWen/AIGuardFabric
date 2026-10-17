import { act, cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import { cloudApi } from '@/api/cloud';
import AliCloudPage from '../../AliCloudPage';
import type * as Client from '@/api/client';

vi.mock('@/api/client', async () => ({ ...await vi.importActual<typeof Client>('@/api/client'),
  useApiQuery: () => ({ data: { data: [] }, isLoading: false, refetch: vi.fn() }) }));
vi.mock('../CloudConnections', () => ({ default: () => null }));
vi.mock('./MseInventoryPanel', () => ({ default: () => <div>Independent read-only MSE inventory</div> }));
afterEach(async () => { cleanup(); vi.restoreAllMocks(); await act(async () => { await i18n.changeLanguage('zh-CN'); }); });

it('opens the bookmarked MSE tab independently of write-restricted connection configuration', async () => {
  await i18n.changeLanguage('en-US'); const configuration = vi.spyOn(cloudApi, 'configuration');
  await act(async () => { render(<MemoryRouter initialEntries={['/alicloud?tab=mse']}><AliCloudPage /></MemoryRouter>); });
  expect(screen.getByRole('tab', { name: 'MSE service inventory' })).toHaveAttribute('aria-selected', 'true');
  expect(screen.getByText('Independent read-only MSE inventory')).toBeInTheDocument(); expect(configuration).not.toHaveBeenCalled();
});
