import { render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import type { ApiKey } from '@/types/domain';
import { ApiKeysTab } from './ApiKeysTab';

it('shows key management actions only to a settings administrator', async () => {
  await i18n.changeLanguage('zh-CN');
  const row = { id: 'key-one', name: 'MCP client', prefix: 'agf_test',
    scopes: ['mcps:execute', 'policies:read'], createdAt: '2026-09-26T00:00:00Z',
    expiresAt: null, lastUsedAt: null, revoked: false, boundAgentId: null } as ApiKey;
  const props = { loading: false, error: null, apiKeys: [row],
    onCreateKey: vi.fn(), onRevoked: vi.fn() };
  const view = render(<ApiKeysTab {...props} canManage={false} />);
  expect(screen.getByText('MCP client')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: '创建 API Key' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /吊\s*销/ })).not.toBeInTheDocument();
  view.rerender(<ApiKeysTab {...props} canManage />);
  expect(screen.getByRole('button', { name: '创建 API Key' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /吊\s*销/ })).toBeInTheDocument();
  view.unmount();
});
