import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import { api, probeBackend } from '@/api/client';
import { ssoApi } from '@/api/sso';
import { useAuthStore } from '@/stores/authStore';
import type { LoginResponse } from '@/types/domain';
import i18n from '@/locales/i18n';
import LoginPage from './LoginPage';

vi.mock('@/api/client', () => ({
  api: { login: vi.fn() }, demoLogin: vi.fn(), probeBackend: vi.fn().mockResolvedValue(true),
  DEMO_CREDENTIALS: { tenantSlug: 'demo', username: 'demo', password: 'demo' },
}));
vi.mock('@/components/DemoModeBanner', () => ({ DemoModeBanner: () => null }));

const originalSetSession = useAuthStore.getState().setSession;
afterEach(() => { vi.restoreAllMocks(); useAuthStore.setState({ setSession: originalSetSession }); useAuthStore.getState().reset(); });

it('sends LDAP credentials only to the directory login endpoint and opens the session', async () => {
  await i18n.changeLanguage('zh-CN');
  vi.mocked(probeBackend).mockResolvedValue(true);
  const setSession = vi.fn();
  useAuthStore.setState({ token: null, setSession });
  const login = vi.spyOn(ssoApi, 'ldapLogin').mockResolvedValue({ data: {
    token: 'test-ldap-token', refreshToken: 'test-refresh-token', mustChangePassword: false,
    mfaEnrollmentRequired: false,
    user: { id: 'user-id', displayName: 'Alice', role: 'viewer' },
    tenant: { id: 'tenant-id', slug: 'default' },
  } as LoginResponse, meta: { source: 'live', elapsedMs: 1, at: 1 } });
  const view = render(<MemoryRouter initialEntries={['/login']}><Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route path="/" element={<div>Signed in</div>} />
  </Routes></MemoryRouter>);
  const button = await screen.findByRole('button', { name: 'LDAP / AD 登录' });
  fireEvent.change(screen.getByLabelText('用户名'), { target: { value: 'alice' } });
  fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'directory-password' } });
  fireEvent.click(button);
  await waitFor(() => expect(login).toHaveBeenCalledWith(expect.objectContaining({
    tenantSlug: 'default', username: 'alice', password: 'directory-password',
  })));
  expect(api.login).not.toHaveBeenCalled();
  await waitFor(() => expect(setSession).toHaveBeenCalledWith(expect.objectContaining({ token: 'test-ldap-token' })));
  expect(await screen.findByText('Signed in')).toBeInTheDocument();
  view.unmount();
});
