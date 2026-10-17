import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import i18n from '@/locales/i18n';
import { AssetPackageObservation } from './AssetPackageObservation';

afterEach(cleanup);

it('distinguishes a complete directory observation from live integrity or approval', async () => {
  await i18n.changeLanguage('en-US');
  render(<AssetPackageObservation observation={{
    current: { algorithm: 'sha256-tree-v1', status: 'verified', sha256: 'a'.repeat(64), files: 2, bytes: 46 },
    receivedAt: '2026-09-22T12:00:00Z',
  }} />);
  expect(screen.getByText(/Complete observation · 2 files · 46 bytes/)).toBeInTheDocument();
  expect(screen.getByText(/first observation establishes a baseline/)).toBeInTheDocument();
  expect(screen.getByText(/neither live monitoring nor an atomic snapshot/)).toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('labels an unavailable current scan and the retained historical hash in Chinese', async () => {
  await i18n.changeLanguage('zh-CN');
  render(<AssetPackageObservation observation={{
    current: { algorithm: 'sha256-tree-v1', status: 'link-not-allowed' },
    receivedAt: '2026-09-22T12:00:00Z',
    lastVerified: { algorithm: 'sha256-tree-v1', status: 'verified', sha256: 'b'.repeat(64), files: 2, bytes: 46 },
    lastVerifiedAt: '2026-09-21T12:00:00Z',
  }} />);
  expect(screen.getByText('本次未取得完整目录哈希')).toBeInTheDocument();
  expect(screen.getByText(/包含符号链接、目录联接/)).toBeInTheDocument();
  expect(screen.getByText(/上次完整观察（历史记录）/)).toBeInTheDocument();
  expect(screen.getByText('b'.repeat(64))).toBeInTheDocument();
  expect(screen.queryByText(/已完整读取/)).not.toBeInTheDocument();
});
