import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { caseWorkflowsApi, type CaseWorkflow } from '@/api/caseWorkflows';
import CaseWorkflows from './CaseWorkflows';

describe('workflow review', () => {
  it('binds approval to the reviewed revision and retains the reason after a conflict', async () => {
    const meta = { source: 'live' as const, elapsedMs: 1, at: Date.now() };
    const row = { id: 'run-one', caseId: 'case-one', version: 3, status: 'approval', nextStep: 0,
      playbook: { key: 'review', name: 'Review target', steps: [{ name: 'Block reviewed domain', action: 'block-domain', params: { domain: 'reviewed.example' } }] },
      requestedBy: { id: 'submitter', kind: 'user' }, executeAs: { id: 'submitter', kind: 'user' },
      trace: [], history: [], separateApprover: false,
    } as unknown as CaseWorkflow;
    const list = vi.spyOn(caseWorkflowsApi, 'list').mockResolvedValue({ data: { items: [row], total: 1, canWrite: true, canApprove: true, durable: true }, meta });
    const get = vi.spyOn(caseWorkflowsApi, 'get').mockResolvedValue({ data: { run: row }, meta });
    const decide = vi.spyOn(caseWorkflowsApi, 'decide').mockRejectedValue(new Error('执行记录已更新，请刷新后重新核对步骤与目标'));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const rendered = render(<QueryClientProvider client={client}><CaseWorkflows caseId="case-one" refreshToken={0} onChange={vi.fn()} /></QueryClientProvider>);
    fireEvent.click(await screen.findByRole('button', { name: 'Review target' }));
    fireEvent.click(await screen.findByRole('button', { name: /批\s*准/ }));
    const reason = screen.getByRole('textbox', { name: '处理原因' });
    fireEvent.change(reason, { target: { value: 'Only the reviewed target is authorized' } });
    get.mockResolvedValue({ data: { run: { ...row, version: 4 } }, meta });
    await client.invalidateQueries({ predicate: query => query.queryKey.includes('case-workflow') });
    fireEvent.click(screen.getByRole('button', { name: /OK|确\s*定/ }));
    await screen.findByText('执行记录已更新，请刷新后重新核对步骤与目标');
    await waitFor(() => expect(decide).toHaveBeenCalledWith('case-one', 'run-one', 3, 'approve', 'Only the reviewed target is authorized'));
    expect(reason).toHaveValue('Only the reviewed target is authorized');
    rendered.unmount(); client.clear(); list.mockRestore(); get.mockRestore(); decide.mockRestore();
  });
});
