import { render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import i18n from '@/locales/i18n';
import { CrossCallsPanel } from './CrossCallsPanel';

afterEach(async () => { await i18n.changeLanguage('zh-CN'); });
it('keeps unknown authorization neutral and counts only explicit denials', async () => {
  await i18n.changeLanguage('en-US');
  const call = { id: 'call-one', callerTeam: 'first', calleeTeam: 'second', calleeAgent: 'worker',
    count24h: 2, authorized: null, sensitiveData: null };
  const view = render(<CrossCallsPanel loading={false} error={null} calls={[call]} />);
  expect(screen.getAllByText('Unknown')).toHaveLength(2);
  expect(screen.queryByText('No')).not.toBeInTheDocument();
  expect(screen.queryByText(/cross-team calls are unauthorized/)).not.toBeInTheDocument();
  view.rerender(<CrossCallsPanel loading={false} error={null} calls={[call, { ...call, id: 'call-two', authorized: false }]} />);
  expect(screen.getByText(/1 cross-team calls are unauthorized/)).toBeInTheDocument();
  expect(screen.queryByText(/2 cross-team calls are unauthorized/)).not.toBeInTheDocument();
});
