import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RuleEditor } from './RuleEditor';
import { __resetDataSource } from '@/api/client';
import { useAuthStore } from '@/stores/authStore';
import i18n from '@/locales/i18n';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
beforeEach(async () => { __resetDataSource(); await i18n.changeLanguage('en-US'); });
const source = 'key: EXISTING\nname: Current\n';
function install(canWrite: boolean, post: (init: RequestInit) => Response | Promise<Response>) {
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    if (init?.method === 'POST') return post(init);
    return Response.json(url.includes('/versions') ? { items: [{ version: 1, yaml: 'old version', actor: 'admin', changedAt: '' }] }
      : { yaml: source, rule: { version: 2 }, can_write: canWrite });
  }));
}
describe('rule editor publication boundary', () => {
  it('keeps reader access to source and history while disabling publication and restore', async () => {
    const post = vi.fn(); install(false, post);
    render(<RuleEditor ruleKey="EXISTING" canWrite onClose={() => {}} onSaved={() => {}} />);
    await waitFor(() => expect(screen.getByLabelText('Rule YAML')).toHaveValue(source));
    expect(screen.getByLabelText('Rule YAML')).toHaveAttribute('readonly');
    expect(screen.getByRole('button', { name: 'Validate and publish' })).toBeDisabled();
    fireEvent.click(screen.getByRole('tab', { name: 'Revision history' }));
    expect(screen.getByRole('button', { name: 'Restore' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'View contents' }));
    expect(screen.getByLabelText('Rule YAML')).toHaveValue('old version');
    expect(post).not.toHaveBeenCalled();
  });
  it('submits the loaded version and stable key and preserves the draft on 409', async () => {
    let sent: Record<string, unknown> | undefined;
    const saved = vi.fn();
    install(true, init => { sent = JSON.parse(String(init.body)); return Response.json({ detail: 'Another editor saved v3' }, { status: 409 }); });
    render(<RuleEditor ruleKey="EXISTING" canWrite onClose={() => {}} onSaved={saved} />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Validate and publish' })).toBeEnabled());
    fireEvent.change(screen.getByLabelText('Rule YAML'), { target: { value: source + 'description: Keep my edit\n' } });
    fireEvent.click(screen.getByRole('button', { name: 'Validate and publish' }));
    await screen.findByText('Operation failed; your draft is preserved');
    expect(sent).toMatchObject({ sourceKey: 'EXISTING', expectedVersion: 2 });
    expect(screen.getByLabelText('Rule YAML')).toHaveValue(source + 'description: Keep my edit\n');
    expect(saved).not.toHaveBeenCalled();
    expect(screen.getByText(/Another editor saved v3/)).toBeInTheDocument();
  });
  it('ignores a late save response after the session changes', async () => {
    let finish!: (response: Response) => void;
    const pending = new Promise<Response>(resolve => { finish = resolve; });
    const saved = vi.fn(); const closed = vi.fn();
    const post = vi.fn(() => pending); install(true, post);
    render(<RuleEditor ruleKey="" canWrite onClose={closed} onSaved={saved} />);
    const initial = String((screen.getByLabelText('Rule YAML') as HTMLTextAreaElement).value);
    expect(initial).toContain('rollout_percent: 0');
    fireEvent.click(screen.getByRole('button', { name: 'Validate and publish' }));
    fireEvent.click(screen.getByRole('button', { name: 'Validate and publish' }));
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
    act(() => useAuthStore.setState({ sessionGeneration: useAuthStore.getState().sessionGeneration + 1 }));
    await act(async () => { finish(Response.json({ rule: { version: 1 } })); await pending; });
    expect(saved).not.toHaveBeenCalled(); expect(closed).not.toHaveBeenCalled();
  });
});
