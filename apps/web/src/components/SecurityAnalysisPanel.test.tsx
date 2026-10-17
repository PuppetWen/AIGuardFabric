import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { message } from 'antd';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as transport from '@/api/transport';
import { useAuthStore } from '@/stores/authStore';
import { SecurityAnalysisPanel } from './SecurityAnalysisPanel';
import ReportsPage from '../pages/ReportsPage';

const access = vi.hoisted(() => ({ denied: new Set<string>(), language: 'zh-CN' }));
vi.mock('@/api/sessionAccess', () => ({ useSessionAccess: () => ({ has: (scope: string) => !access.denied.has(scope) }) }));
vi.mock('react-i18next', async importOriginal => ({ ...await importOriginal<typeof import('react-i18next')>(), useTranslation: () => ({ t: (key: string) => key,
  i18n: { language: access.language, resolvedLanguage: access.language } }) }));
vi.mock('@/pages/reports/ReportSchedules', () => ({ ReportSchedules: () => null }));

const record = { id: 'saved', model: 'actual-mock-endpoint', mocked: true, cached: false,
  modelResponseUsed: false, contextBudgetTokens: 2048,
  snapshotSha256: 'snapshot-proof', usageRecordId: 'actual-ledger-id', promptTokens: 24, completionTokens: 12,
  costMicroCny: 0, snapshot: { facts: [{ reference: 'alert:owned', kind: 'alert', observedAt: '2026-10-14T10:00:00Z',
    contentHash: null, metadata: { state: 'new' } }], truncated: false, omittedFacts: 0, omittedRecords: 0 },
  assessment: { verdict: 'unknown', confidence: 0, summary: 'Mock demonstration using stored evidence',
    evidenceRefs: ['alert:owned'], observations: [], timeline: [], hypotheses: [] } };
const response = (analysis: unknown) => ({ data: { analysis }, meta: { source: 'live', elapsedMs: 1, at: Date.now() } });
const initialAuth = useAuthStore.getState();
const clients: QueryClient[] = [];
function mount(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  return render(<QueryClientProvider client={client}>{children}</QueryClientProvider>);
}

afterEach(() => {
  cleanup(); clients.splice(0).forEach(client => client.clear()); message.destroy();
  vi.restoreAllMocks(); vi.unstubAllGlobals(); access.denied.clear(); access.language = 'zh-CN';
  useAuthStore.setState(initialAuth);
});

describe('manual grounded model analysis', () => {
  it('shows the derived Mock fixture truth and retains saved analysis when the next provider response fails', async () => {
    const request = vi.spyOn(transport, 'callApi').mockImplementation(async (_path, _fallback, options) => {
      if (options?.method === 'POST') throw new Error('Model did not return the required analysis JSON object');
      return response(record) as never;
    });
    mount(<SecurityAnalysisPanel resource="alerts" id="owned" />);
    await screen.findByText('Mock 演示');
    expect(screen.getByText('静态未知结论示例')).toBeInTheDocument();
    expect(request.mock.calls.some(call => call[2]?.method === 'POST')).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: '研判当前证据' }));
    await screen.findByText('Model did not return the required analysis JSON object');
    expect(screen.queryByText('实际模型调用')).not.toBeInTheDocument();
    expect(screen.getByText(record.assessment.summary)).toBeInTheDocument();
    const write = request.mock.calls.find(call => call[2]?.method === 'POST');
    expect(write?.[0]).toBe('/api/v1/alerts/owned/analysis');
    expect(write?.[2]).toMatchObject({ noFallback: true, body: {}, timeoutMs: 45_000 });
    fireEvent.click(screen.getByText('来源与实际用量'));
    await screen.findByText('actual-ledger-id');
    expect(screen.getByText('24 / 12')).toBeInTheDocument();
    expect(screen.getByText('费用（微人民币）').closest('tr')).toHaveTextContent('0');
  });

  it.each(['models:write', 'cases:write', 'cases:read'])('requires %s and never executes a denied manual action', async permission => {
    access.denied.add(permission);
    const request = vi.spyOn(transport, 'callApi').mockResolvedValue(response(null) as never);
    mount(<SecurityAnalysisPanel resource="cases" id="owned" />);
    await waitFor(() => expect(screen.getByRole('button', { name: '研判当前证据' })).toBeDisabled());
    fireEvent.click(screen.getByRole('button', { name: '研判当前证据' }));
    expect(request.mock.calls.some(call => call[2]?.method === 'POST')).toBe(false);
  });

  it('refreshes saved real analysis only after an explicit action and shows bounded input and hypotheses', async () => {
    access.language = 'en-US';
    const live = { ...record, model: 'configured-live-model', mocked: false, modelResponseUsed: true, costMicroCny: 137,
      snapshot: { ...record.snapshot, truncated: true, omittedFacts: 3, omittedRecords: 2,
        facts: [...record.snapshot.facts, { ...record.snapshot.facts[0], reference: 'event:owned', kind: 'event' }] },
      assessment: { ...record.assessment, summary: 'Stored evidence needs review',
        timeline: [{ evidenceRef: 'alert:owned', explanation: 'Interpretation at the stored timestamp' }],
        hypotheses: [{ fromRef: 'alert:owned', toRef: 'event:owned', explanation: 'Possible relationship' }] } };
    let saved = false;
    const request = vi.spyOn(transport, 'callApi').mockImplementation(async (_path, _fallback, options) => {
      if (options?.method === 'POST') saved = true;
      return response(saved ? live : null) as never;
    });
    mount(<SecurityAnalysisPanel resource="alerts" id="owned / 1" />);
    await screen.findByText('No saved model review for this object.');
    fireEvent.click(screen.getByRole('button', { name: 'Review stored evidence' }));
    await screen.findByText('Actual model call');
    expect(screen.queryByText('Derived unknown fixture')).not.toBeInTheDocument();
    expect(screen.getByText('Model input: 2 evidence facts; 3 facts and 2 records omitted.')).toBeInTheDocument();
    expect(screen.getByText('Unverified hypothesis')).toBeInTheDocument();
    expect(screen.getByText('2026-10-14T10:00:00Z')).toBeInTheDocument();
    expect(request.mock.calls.map(call => call[0])).toEqual(Array(3).fill('/api/v1/alerts/owned%20%2F%201/analysis'));
    fireEvent.click(screen.getByText('Evidence snapshot supplied to the model'));
    await screen.findByText('event:owned');
    expect(screen.getAllByText(/"state": "new"/)).toHaveLength(2);
    fireEvent.click(screen.getByText('Provenance and actual usage'));
    await screen.findByText('Cost (micro CNY)');
    expect(screen.getByText('137')).toBeInTheDocument();
  });

  it('surfaces a saved-analysis read failure without manufacturing demo analysis', async () => {
    const request = vi.spyOn(transport, 'callApi').mockRejectedValue(new Error('Evidence access denied'));
    mount(<SecurityAnalysisPanel resource="alerts" id="owned" />);
    await screen.findByText('Evidence access denied');
    expect(screen.queryByText('Mock 演示')).not.toBeInTheDocument();
    expect(request).toHaveBeenCalledWith('/api/v1/alerts/owned/analysis', expect.any(Function), { noFallback: true, opaqueKeys: ['metadata'] });
  });

  it('does not announce an old save when the session changes while its refresh waits', async () => {
    let finishRefresh!: (value: ReturnType<typeof response>) => void;
    let reads = 0;
    const success = vi.spyOn(message, 'success');
    vi.spyOn(transport, 'callApi').mockImplementation(async (_path, _fallback, options) => {
      if (options?.method !== 'POST' && ++reads === 2) return new Promise(resolve => { finishRefresh = resolve; }) as never;
      return response(record) as never;
    });
    mount(<SecurityAnalysisPanel resource="alerts" id="owned" />);
    await screen.findByText('Mock 演示');
    fireEvent.click(screen.getByRole('button', { name: '研判当前证据' }));
    await waitFor(() => expect(reads).toBe(2));
    await act(async () => {
      useAuthStore.setState({ sessionGeneration: initialAuth.sessionGeneration + 1 });
      finishRefresh(response(record));
    });
    expect(success).not.toHaveBeenCalled();
  });
});

describe('manual report model opt-in', () => {
  async function openWizard() {
    const request = vi.spyOn(transport, 'callApi').mockResolvedValue({ data: { items: [], total: 0 },
      meta: { source: 'live', elapsedMs: 1, at: Date.now() } } as never);
    mount(<ReportsPage />);
    fireEvent.click(screen.getByRole('button', { name: /reports.wizard.button/ }));
    fireEvent.click(await screen.findByRole('button', { name: 'common.next' }));
    await screen.findByRole('spinbutton');
    fireEvent.click(screen.getByRole('button', { name: 'common.next' }));
    const checkbox = await screen.findByRole('checkbox');
    return { request, checkbox };
  }

  it('defaults off and generates an ordinary report without model_assisted', async () => {
    const { request, checkbox } = await openWizard();
    expect(checkbox).not.toBeChecked();
    fireEvent.click(screen.getByRole('button', { name: 'common.next' }));
    await screen.findByText('未启用');
    fireEvent.click(screen.getByRole('button', { name: 'common.generate' }));
    await waitFor(() => expect(request.mock.calls.some(call => call[2]?.method === 'POST')).toBe(true));
    expect(request.mock.calls.find(call => call[2]?.method === 'POST')?.[2]?.body).toEqual({
      kind: 'posture', window_secs: 30 * 86400, format: 'markdown',
    });
  });

  it('sends model_assisted only after explicit opt-in, with an honest usage label and model timeout', async () => {
    const { request, checkbox } = await openWizard();
    fireEvent.click(checkbox);
    fireEvent.click(screen.getByRole('button', { name: 'common.next' }));
    await screen.findByText('已启用：实际用量计费，Mock 会明确标注');
    fireEvent.click(screen.getByRole('button', { name: 'common.generate' }));
    await waitFor(() => expect(request.mock.calls.some(call => call[2]?.method === 'POST')).toBe(true));
    expect(request.mock.calls.find(call => call[2]?.method === 'POST')?.[2]).toMatchObject({
      noFallback: true, timeoutMs: 45_000, body: { kind: 'posture', window_secs: 30 * 86400, format: 'markdown', model_assisted: true },
    });
  });

  it('disables model opt-in without model write permission', async () => {
    access.denied.add('models:write');
    const { checkbox } = await openWizard();
    expect(checkbox).toBeDisabled();
    expect(checkbox).not.toBeChecked();
  });

  it('remounts the report wizard on a session change in the same organization', async () => {
    let finishWrite!: (value: unknown) => void;
    const { request, checkbox } = await openWizard();
    const success = vi.spyOn(message, 'success');
    request.mockImplementation(async (_path, _fallback, options) => {
      if (options?.method === 'POST') return new Promise(resolve => { finishWrite = resolve; }) as never;
      return { data: { items: [], total: 0 }, meta: { source: 'live', elapsedMs: 1, at: Date.now() } } as never;
    });
    fireEvent.click(checkbox);
    fireEvent.click(screen.getByRole('button', { name: 'common.next' }));
    fireEvent.click(await screen.findByRole('button', { name: 'common.generate' }));
    await waitFor(() => expect(finishWrite).toBeDefined());
    await act(async () => {
      useAuthStore.setState({ sessionGeneration: initialAuth.sessionGeneration + 1 });
      finishWrite({ data: { report: {} }, meta: { source: 'live', elapsedMs: 1, at: Date.now() } });
    });
    expect(success).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.queryByRole('button', { name: 'common.generate' })).not.toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /reports.wizard.button/ }));
    fireEvent.click(await screen.findByRole('button', { name: 'common.next' }));
    await screen.findByRole('spinbutton');
    fireEvent.click(await screen.findByRole('button', { name: 'common.next' }));
    expect(await screen.findByRole('checkbox')).not.toBeChecked();
  });
});
