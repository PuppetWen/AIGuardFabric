import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';

import i18n from '@/locales/i18n';
import { __resetDataSource } from '@/api/client';

import AliCloudPage from '@/pages/AliCloudPage';
import AgentsPage from '@/pages/AgentsPage';
import AuditPage from '@/pages/AuditPage';
import CasesPage from '@/pages/CasesPage';
import FindingsPage from '@/pages/FindingsPage';
import IntegrationsPage from '@/pages/IntegrationsPage';
import McpsPage from '@/pages/McpsPage';
import PoliciesPage from '@/pages/PoliciesPage';
import ReportsPage from '@/pages/ReportsPage';
import RulesPage from '@/pages/RulesPage';

/**
 * Offline render smoke test.
 *
 * Failed inventory requests must show an error without substituting sample assets.
 * Legacy pages that explicitly allow demo fallback retain their separate smoke cases.
 */
function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 0, gcTime: 0 } },
  });
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

const CASES: { name: string; element: ReactNode; expectText: string; realOnly?: boolean }[] = [
  { name: 'AgentsPage', element: <AgentsPage />, expectText: '客服智能助手 Copilot', realOnly: true },
  { name: 'McpsPage', element: <McpsPage />, expectText: 'shell-mcp', realOnly: true },
  { name: 'FindingsPage', element: <FindingsPage />, expectText: '影子 MCP 暴露任意命令执行工具' },
  { name: 'RulesPage', element: <RulesPage />, expectText: '高危工具暴露检测' },
  { name: 'PoliciesPage', element: <PoliciesPage />, expectText: '出网域名黑名单阻断' },
  { name: 'CasesPage', element: <CasesPage />, expectText: '影子 MCP 命令执行面处置' },
  { name: 'IntegrationsPage', element: <IntegrationsPage />, expectText: 'OpenAI 兼容网关' },
  { name: 'AliCloudPage', element: <AliCloudPage />, expectText: '客服运营团队', realOnly: true },
  { name: 'AuditPage', element: <AuditPage />, expectText: 'policy.update' },
  { name: 'ReportsPage', element: <ReportsPage />, expectText: '2025 年 3 月管理层态势报表' },
];

describe('pages handle an unreachable backend', () => {
  for (const { name, element, expectText, realOnly } of CASES) {
    it(`${name} ${realOnly ? 'shows an error without sample assets' : 'renders its allowed demo content'}`, async () => {
      __resetDataSource();
      vi.stubGlobal(
        'fetch',
        vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))),
      );
      await i18n.changeLanguage('zh-CN');

      render(<Wrapper>{element}</Wrapper>);

      await waitFor(
        () => {
          expect(screen.getAllByText(realOnly ? /Network error for \/api\/v1\// : new RegExp(expectText)).length).toBeGreaterThan(0);
          if (realOnly) expect(screen.queryByText(new RegExp(expectText))).toBeNull();
        },
        { timeout: 8_000 },
      );
    });
  }
});
