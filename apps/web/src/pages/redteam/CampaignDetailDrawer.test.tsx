import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import * as transport from '@/api/transport';
import i18n from '@/locales/i18n';
import type { CampaignResult } from '@/types/domain';
import { CampaignDetailDrawer } from './CampaignDetailDrawer';

let findingRow: CampaignResult | null = null;
vi.mock('@/api/client', () => ({
  api: {},
  useApiQuery: (key: string) => ({
    data: key === 'campaign-detail' ? { data: {
      id: 'campaign-1', name: 'Baseline', status: 'succeeded', state: 'completed',
      executionMode: 'agent-http', targetProfileId: 'target-1', targetName: 'Fixture Agent',
      totalCases: 1, succeeded: 1, ciGateEnabled: true, severityThreshold: 'critical',
    } } : key === 'retest-agent-targets' ? { data: { items: [
      { id: 'target-1', name: 'Fixture Agent', version: 2, enabled: true },
    ] } } : key === 'campaign-results' ? { data: findingRow ? [findingRow] : [] } : { data: { markdown: null } },
    isLoading: false, error: null, refetch: vi.fn(),
  }),
}));

afterEach(() => { cleanup(); vi.restoreAllMocks(); findingRow = null; });

it('links an observed live result to the reviewable finding', async () => {
  await i18n.changeLanguage('en-US');
  findingRow = {
    id: 'result-1', campaignId: 'campaign-1', caseId: 'RT-MCP-001', category: 'credential-theft',
    target: 'asset-1', severity: 'critical', outcome: 'succeeded', bypassPath: [],
    payload: '', modelResponse: '', evidenceRef: 'campaign:campaign-1/results/result-1',
    findingId: 'finding-123', matchedSignals: ['credential_in_output'], ranAt: new Date().toISOString(),
  };
  render(<MemoryRouter><CampaignDetailDrawer selectedId="campaign-1" canExecute canUseAgentTarget
    onClose={vi.fn()} onRetest={vi.fn()} /></MemoryRouter>);
  expect((await screen.findByRole('link', { name: 'Review finding' })).getAttribute('href'))
    .toBe('/findings?finding=finding-123');
  expect(screen.getByRole('link', { name: 'View linked alerts and cases' }).getAttribute('href'))
    .toBe('/alerts?q=redteam%3Acampaign-1%3A');
});

it('retests the saved real Agent cases against the current target revision', async () => {
  await i18n.changeLanguage('en-US');
  const send = vi.spyOn(transport, 'callApi').mockResolvedValue({ data: { taskId: 'campaign-2' },
    meta: { source: 'live', elapsedMs: 1, at: Date.now() } });
  const onRetest = vi.fn();
  render(<CampaignDetailDrawer selectedId="campaign-1" canExecute canUseAgentTarget
    onClose={vi.fn()} onRetest={onRetest} />);
  fireEvent.click(screen.getByRole('button', { name: 'Retest saved cases' }));
  expect(await screen.findByText('Fixture Agent · v2')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Submit retest' }));
  await waitFor(() => expect(onRetest).toHaveBeenCalledWith('campaign-2'));
  expect(send).toHaveBeenCalledWith('/api/v1/redteam/campaigns/campaign-1/retest', expect.any(Function),
    expect.objectContaining({ noFallback: true,
      body: { name: 'Baseline retest', target_profile_version: 2 } }));
});
