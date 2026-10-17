import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { casesApi } from '@/api/cases';
import { caseWorkflowsApi } from '@/api/caseWorkflows';
import type { Case } from '@/types/domain';
import CaseActions from './CaseActions';

describe('case execution results', () => {
  it('labels dry runs and displays executor failures without claiming completion', async () => {
    const meta = { source: 'live' as const, elapsedMs: 1, at: Date.now() };
    const controls = vi.spyOn(casesApi, 'controls').mockResolvedValue({ data: { items: [], canWrite: true, canRelease: true }, meta });
    const runs = vi.spyOn(caseWorkflowsApi, 'list').mockResolvedValue({ data: { items: [], total: 0, canWrite: true, canApprove: true, durable: true }, meta });
    const execute = vi.spyOn(casesApi, 'execute').mockResolvedValue({ data: {
      outcome: 'aborted', dryRun: true, hasFailure: true, runId: 'failure-run',
      steps: [{ name: 'Invalid action', outcome: 'failed', error: 'Target is not configured', note: '' }],
    }, meta });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const change = vi.fn();
    const rendered = render(<QueryClientProvider client={client}><CaseActions item={{ id: 'case-id', assetNames: [] } as unknown as Case} onChange={change} /></QueryClientProvider>);
    await waitFor(() => expect(screen.getByText('执行处置 / YAML 剧本').closest('button')).not.toBeDisabled());
    fireEvent.click(screen.getByText('执行处置 / YAML 剧本'));
    fireEvent.click(screen.getByText('使用 YAML 剧本'));
    fireEvent.change(screen.getByPlaceholderText(/key: isolate-agent/), { target: { value: 'key: example' } });
    fireEvent.click(screen.getByRole('button', { name: /演\s*练$/ }));
    await screen.findByText('演练结果：aborted');
    await screen.findByText('Invalid action: Target is not configured');
    await waitFor(() => expect(execute).toHaveBeenCalledWith('case-id', { yaml: 'key: example', dry_run: true, approve: false }));
    expect(change).toHaveBeenCalledOnce();
    expect(screen.getByRole('button', { name: /演\s*练$/ })).toBeDisabled();
    rendered.unmount(); client.clear(); controls.mockRestore(); execute.mockRestore(); runs.mockRestore();
  });
});
