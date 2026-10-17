import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

import { OIDC_STORAGE_KEY, ssoApi, type OidcFlow } from '@/api/sso';
import i18n from '@/locales/i18n';
import { useAuthStore } from '@/stores/authStore';
import type { LoginResponse } from '@/types/domain';
import OidcCallbackPage from './OidcCallbackPage';
import SamlCallbackPage from './SamlCallbackPage';

afterEach(() => {
  cleanup();
  sessionStorage.clear();
  vi.restoreAllMocks();
  useAuthStore.getState().reset();
});

describe('enterprise sign-in callbacks', () => {
  it('explains an incomplete OIDC sign-in in English and returns to sign-in', async () => {
    await i18n.changeLanguage('en-US');
    window.history.replaceState({}, '', '/login/oidc/callback?error=access_denied');
    render(<MemoryRouter initialEntries={['/login/oidc/callback']}><Routes>
      <Route path="/login/oidc/callback" element={<OidcCallbackPage />} />
      <Route path="/login" element={<div>Sign-in page</div>} />
    </Routes></MemoryRouter>);
    expect(await screen.findByText(/Enterprise sign-in was not completed/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Enterprise sign-in' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Back to sign-in' }));
    expect(await screen.findByText('Sign-in page')).toBeInTheDocument();
  });

  it('explains an unstarted SAML sign-in in English and returns to sign-in', async () => {
    await i18n.changeLanguage('en-US');
    window.history.replaceState({}, '', '/login/saml/callback');
    render(<MemoryRouter initialEntries={['/login/saml/callback']}><Routes>
      <Route path="/login/saml/callback" element={<SamlCallbackPage />} />
      <Route path="/login" element={<div>Sign-in page</div>} />
    </Routes></MemoryRouter>);
    expect(await screen.findByText(/SAML sign-in was not started/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Enterprise SAML sign-in' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Back to sign-in' }));
    expect(await screen.findByText('Sign-in page')).toBeInTheDocument();
  });

  it('accepts a completed OIDC exchange once and opens the console', async () => {
    await i18n.changeLanguage('en-US');
    const flow: OidcFlow = { tenantSlug: 'default', state: 'state-1', binding: 'browser-1', createdAt: Date.now() };
    sessionStorage.setItem(OIDC_STORAGE_KEY, JSON.stringify(flow));
    window.history.replaceState({}, '', '/login/oidc/callback?state=state-1&code=code-1');
    const exchange = vi.spyOn(ssoApi, 'exchange').mockResolvedValue({
      data: { mfaRequired: false }, meta: { source: 'live', elapsedMs: 1, at: 1 },
    });
    const complete = vi.spyOn(ssoApi, 'complete').mockResolvedValue({
      token: 'session-token', refreshToken: 'refresh-token', mustChangePassword: false,
      mfaEnrollmentRequired: false, user: { id: 'user-id', displayName: 'User', role: 'viewer' },
      tenant: { id: 'tenant-id', slug: 'default' },
    } as LoginResponse);
    render(<MemoryRouter initialEntries={['/login/oidc/callback']}><Routes>
      <Route path="/login/oidc/callback" element={<OidcCallbackPage />} />
      <Route path="/" element={<div>Signed in</div>} />
    </Routes></MemoryRouter>);
    expect(await screen.findByText('Signed in')).toBeInTheDocument();
    expect(exchange).toHaveBeenCalledOnce();
    expect(exchange).toHaveBeenCalledWith(flow, 'code-1');
    expect(complete).toHaveBeenCalledOnce();
    await waitFor(() => expect(useAuthStore.getState().token).toBe('session-token'));
    expect(sessionStorage.getItem(OIDC_STORAGE_KEY)).toBeNull();
    expect(window.location.search).toBe('');
  });
});
