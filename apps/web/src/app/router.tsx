import { Suspense, lazy, useEffect, type ReactNode } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import { Button, Result, Skeleton } from 'antd';

import { AppLayout } from '@/components/AppLayout';
import { PageErrorBoundary } from '@/components/PageErrorBoundary';
import { useAuthStore } from '@/stores/authStore';

/* Route-level code splitting: each page becomes its own chunk. */
const LoginPage = lazy(() => import('@/pages/LoginPage'));
const OidcCallbackPage = lazy(() => import('@/pages/login/OidcCallbackPage'));
const McpOAuthCallbackPage = lazy(() => import('@/pages/mcp/McpOAuthCallbackPage'));
const SamlCallbackPage = lazy(() => import('@/pages/login/SamlCallbackPage'));
const QrApprovePage = lazy(() => import('@/pages/login/QrApprovePage'));
const OverviewPage = lazy(() => import('@/pages/OverviewPage'));
const AssetsPage = lazy(() => import('@/pages/AssetsPage'));
const AgentsPage = lazy(() => import('@/pages/AgentsPage'));
const McpsPage = lazy(() => import('@/pages/McpsPage'));
const SkillsPage = lazy(() => import('@/pages/SkillsPage'));
const ModelsPage = lazy(() => import('@/pages/ModelsPage'));
const TopologyPage = lazy(() => import('@/pages/TopologyPage'));
const FindingsPage = lazy(() => import('@/pages/FindingsPage'));
const RulesPage = lazy(() => import('@/pages/RulesPage'));
const RedTeamPage = lazy(() => import('@/pages/RedTeamPage'));
const PoliciesPage = lazy(() => import('@/pages/PoliciesPage'));
const RuntimePage = lazy(() => import('@/pages/RuntimePage'));
const IngestPage = lazy(() => import('@/pages/IngestPage'));
const AlertsPage = lazy(() => import('@/pages/AlertsPage'));
const CasesPage = lazy(() => import('@/pages/CasesPage'));
const IntegrationsPage = lazy(() => import('@/pages/IntegrationsPage'));
const AliCloudPage = lazy(() => import('@/pages/AliCloudPage'));
const AuditPage = lazy(() => import('@/pages/AuditPage'));
const ReportsPage = lazy(() => import('@/pages/ReportsPage'));
const SettingsPage = lazy(() => import('@/pages/SettingsPage'));
const GuidePage = lazy(() => import('@/pages/GuidePage'));
const AccountSecurityPage = lazy(() => import('@/pages/AccountSecurityPage'));

function RouteFallback() {
  return (
    <div className="agf-panel agf-panel--pad" aria-busy="true">
      <Skeleton active paragraph={{ rows: 6 }} />
    </div>
  );
}

/** Redirects anonymous visitors to `/login`, preserving the intended path. */
function RequireAuth({ children }: { children: ReactNode }) {
  const token = useAuthStore((state) => state.token);
  const location = useLocation();

  if (!token) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <>{children}</>;
}

function NotFoundPage() {
  const { t } = useTranslation();
  return (
    <Result
      status="404"
      title="404"
      subTitle={t('layout.pageNotFoundHint')}
      extra={
        <Button type="primary" href="/">
          {t('nav.overview')}
        </Button>
      }
    />
  );
}

/** Keeps `<html lang>` in sync with the active locale. */
function HtmlLangSync() {
  const { i18n } = useTranslation();
  useEffect(() => {
    document.documentElement.lang = i18n.language;
  }, [i18n.language]);
  return null;
}

/** Public pages and authentication callbacks need the same import-failure recovery. */
function RouteErrorBoundary({ children }: { children: ReactNode }) {
  const location = useLocation();
  return <PageErrorBoundary resetKey={location.pathname}>{children}</PageErrorBoundary>;
}

export function AppRouter() {
  return (
    <BrowserRouter>
      <HtmlLangSync />
      <RouteErrorBoundary>
        <Suspense fallback={<RouteFallback />}>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/login/oidc/callback" element={<OidcCallbackPage />} />
            <Route path="/mcp/oauth/callback" element={<McpOAuthCallbackPage />} />
            <Route path="/login/saml/callback" element={<SamlCallbackPage />} />
            <Route path="/login/qr/approve" element={<QrApprovePage />} />
            <Route path="/security" element={<RequireAuth><AccountSecurityPage /></RequireAuth>} />
            <Route
              path="/"
              element={
                <RequireAuth>
                  <AppLayout />
                </RequireAuth>
              }
            >
              <Route index element={<OverviewPage />} />
              <Route path="assets" element={<AssetsPage />} />
              <Route path="assets/:assetId" element={<AssetsPage />} />
              <Route path="agents" element={<AgentsPage />} />
              <Route path="mcps" element={<McpsPage />} />
              <Route path="skills" element={<SkillsPage />} />
              <Route path="models" element={<ModelsPage />} />
              <Route path="topology" element={<TopologyPage />} />
              <Route path="findings" element={<FindingsPage />} />
              <Route path="rules" element={<RulesPage />} />
              <Route path="redteam" element={<RedTeamPage />} />
              <Route path="policies" element={<PoliciesPage />} />
              <Route path="runtime" element={<RuntimePage />} />
              <Route path="ingest" element={<IngestPage />} />
              <Route path="alerts" element={<AlertsPage />} />
              <Route path="cases" element={<CasesPage />} />
              <Route path="cases/:id" element={<CasesPage />} />
              <Route path="integrations" element={<IntegrationsPage />} />
              <Route path="alicloud" element={<AliCloudPage />} />
              <Route path="audit" element={<AuditPage />} />
              <Route path="reports" element={<ReportsPage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="guide" element={<GuidePage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </Suspense>
      </RouteErrorBoundary>
    </BrowserRouter>
  );
}

export default AppRouter;
