import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import SettingsPage from './SettingsPage';

vi.mock('@/api/sessionAccess', () => ({
  useSessionAccess: () => ({ has: (permission: string) => permission === 'settings:admin',
    identity: { superadmin: false } }),
}));
vi.mock('@/api/client', () => ({
  api: {},
  useApiQuery: () => ({ data: { data: [] }, isLoading: false, isFetching: false,
    error: null, refetch: vi.fn() }),
}));

it('opens the key form with only the scopes requested by an onboarding guide', async () => {
  await i18n.changeLanguage('en-US');
  const view = render(<MemoryRouter initialEntries={[
    '/settings?tab=apiKeys&createKey=1&scopes=sources%3Awrite%2Cplatform%3Aadmin',
  ]}><SettingsPage /></MemoryRouter>);
  expect(await screen.findByRole('dialog', { name: 'Create API key' })).toBeInTheDocument();
  expect(screen.getByText('sources:write')).toBeInTheDocument();
  expect(screen.queryByText('platform:admin')).not.toBeInTheDocument();
  view.unmount();
  await i18n.changeLanguage('zh-CN');
});
