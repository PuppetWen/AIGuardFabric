import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import { probeBackend } from '@/api/client';
import { ssoApi } from '@/api/sso';
import { useAuthStore } from '@/stores/authStore';
import type { LoginResponse } from '@/types/domain';
import i18n from '@/locales/i18n';
import LoginPage from '../LoginPage';
import QrApprovePage from './QrApprovePage';

vi.mock('@/api/client', () => ({
  api: { login: vi.fn() }, demoLogin: vi.fn(), probeBackend: vi.fn().mockResolvedValue(true),
  DEMO_CREDENTIALS: { tenantSlug: 'demo', username: 'demo', password: 'demo' },
}));
vi.mock('@/components/DemoModeBanner', () => ({ DemoModeBanner: () => null }));

const meta = { source: 'live' as const, elapsedMs: 1, at: 1 };
const originalSetSession = useAuthStore.getState().setSession;
afterEach(() => {
  vi.restoreAllMocks();
  useAuthStore.setState({ setSession: originalSetSession });
  useAuthStore.getState().reset();
});

it('shows a short-lived QR flow and signs the approved browser in once', async () => {
  await i18n.changeLanguage('zh-CN');
  vi.mocked(probeBackend).mockResolvedValue(true);
  const setSession = vi.fn();
  useAuthStore.setState({ token: null, setSession });
  const start = vi.spyOn(ssoApi, 'qrStart').mockResolvedValue({ data: {
    state: 'flow-1', binding: 'browser-secret', expiresAt: Math.floor(Date.now() / 1000) + 180,
  }, meta });
  const status = vi.spyOn(ssoApi, 'qrStatus').mockResolvedValue({ data: {
    status: 'approved', expiresAt: Math.floor(Date.now() / 1000) + 180,
  }, meta });
  const complete = vi.spyOn(ssoApi, 'qrComplete').mockResolvedValue({
    token: 'new-browser-token', refreshToken: 'new-browser-refresh', mustChangePassword: false,
    mfaEnrollmentRequired: false, user: { id: 'viewer-id', displayName: 'Viewer', role: 'viewer' },
    tenant: { id: 'tenant-id', slug: 'default' },
  } as LoginResponse);
  const view = render(<MemoryRouter initialEntries={['/login']}><Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route path="/" element={<div>Signed in</div>} />
  </Routes></MemoryRouter>);
  fireEvent.click(await screen.findByRole('button', { name: '手机扫码登录' }));
  await waitFor(() => expect(start).toHaveBeenCalledWith('default'));
  await waitFor(() => expect(status).toHaveBeenCalledWith(expect.objectContaining({
    tenantSlug: 'default', state: 'flow-1', binding: 'browser-secret',
  })), { timeout: 4000 });
  await waitFor(() => expect(complete).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(setSession).toHaveBeenCalledWith(expect.objectContaining({ token: 'new-browser-token' })));
  expect(await screen.findByText('Signed in')).toBeInTheDocument();
  view.unmount();
});

it('requires an authenticated phone to preview and explicitly approve with MFA', async () => {
  await i18n.changeLanguage('zh-CN');
  useAuthStore.setState({ token: 'phone-token', displayName: 'Viewer' });
  const preview = vi.spyOn(ssoApi, 'qrPreview').mockResolvedValue({ data: {
    status: 'pending', expiresAt: Math.floor(Date.now() / 1000) + 180, userName: 'Viewer',
  }, meta });
  const approve = vi.spyOn(ssoApi, 'qrApprove').mockResolvedValue({ data: { approved: true }, meta });
  const view = render(<MemoryRouter initialEntries={['/login/qr/approve?tenant=default&state=flow-1']}><Routes>
    <Route path="/login/qr/approve" element={<QrApprovePage />} />
    <Route path="/login" element={<div>Phone sign-in</div>} />
  </Routes></MemoryRouter>);
  await waitFor(() => expect(preview).toHaveBeenCalledWith('default', 'flow-1'));
  fireEvent.change(await screen.findByLabelText('平台 MFA 验证码或恢复码'), { target: { value: '123456' } });
  fireEvent.click(screen.getByRole('button', { name: '批准这次登录' }));
  await waitFor(() => expect(approve).toHaveBeenCalledWith('default', 'flow-1', '123456'));
  expect(await screen.findByText('已批准，请返回新浏览器')).toBeInTheDocument();
  view.unmount();
});
