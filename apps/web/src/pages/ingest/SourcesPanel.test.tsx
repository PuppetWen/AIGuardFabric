import { act, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it } from 'vitest';
import i18n from '@/locales/i18n';
import type { LogSource } from '@/types/domain';
import { SourcesPanel } from './SourcesPanel';

afterEach(async () => { await act(async () => { await i18n.changeLanguage('zh-CN'); }); });

it('shows the English webhook guide with hidden key entry and an asset-linked event example', async () => {
  await i18n.changeLanguage('en-US');
  const source = {
    id: 'source-one', name: 'Tool events', protocol: 'http-webhook', mode: 'push',
    endpoint: '/api/v1/ingest/sources/source-one/events', parserId: '',
    health: 'healthy', enabled: true, eventsPerSec: 0, lastEventAt: '',
    droppedEvents24h: 0,
  } as LogSource;
  render(<MemoryRouter><SourcesPanel canWrite loading={false} error={null} sources={[source]}
    total={1} page={1} query="" onQuery={() => undefined} onPage={() => undefined}
    onSelectReplay={() => undefined} onEdit={() => undefined} onRefetch={() => undefined} />
  </MemoryRouter>);
  fireEvent.click(screen.getByRole('button', { name: 'Connection guide' }));
  expect(await screen.findByText('Create a tenant ingest API key')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Settings → API keys' })).toHaveAttribute('href',
    '/settings?tab=apiKeys&createKey=1&scopes=sources%3Awrite');
  expect(screen.getByText((_, element) => element?.tagName === 'PRE' &&
    element.textContent?.includes("Read-Host 'Tenant sources:write API key' -AsSecureString") === true)).toBeInTheDocument();
  expect(screen.getByText(/map message → message/)).toBeInTheDocument();
  expect(screen.getAllByText(/MCP_ASSET_UUID/).length).toBeGreaterThan(0);
});
