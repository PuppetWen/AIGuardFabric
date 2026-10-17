import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import * as transport from '@/api/transport';
import i18n from '@/locales/i18n';
import type { Skill } from '@/types/domain';
import { SkillReviewModal } from './SkillReviewModal';

const skill = { id: 'skill-one', name: 'Finance review', status: 'pending',
  whitelist: { domains: ['api.example.test'], paths: ['C:\\Program Files\\Tools\\*'] },
  review: { lifecycle: 'trial', allowedNext: ['production', 'archived'], updatedAt: '2026-09-22T10:00:00Z',
    owner: 'alice', department: 'Finance', dataClass: 'confidential' },
} as Skill;
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
it('retains a conflicting draft and original revision without automatic retry', async () => {
  await i18n.changeLanguage('en-US');
  const request = vi.spyOn(transport, 'callApi').mockRejectedValue(new transport.ApiRequestError('stale revision', 409, 'conflict'));
  const onSaved = vi.fn();
  render(<SkillReviewModal skill={skill} mode="review" canWrite onClose={vi.fn()} onSaved={onSaved} />);
  fireEvent.change(screen.getByLabelText('Review note'), { target: { value: 'Reviewed payment data' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await screen.findByText('stale revision');
  expect(screen.getByLabelText('Review note')).toHaveValue('Reviewed payment data');
  expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
  expect(request).toHaveBeenCalledTimes(1);
  expect(request).toHaveBeenCalledWith('/api/v1/skills/skill-one/status', expect.any(Function),
    expect.objectContaining({ noFallback: true, body: expect.objectContaining({
      to: 'production', expected_updated_at: '2026-09-22T10:00:00Z', note: 'Reviewed payment data',
      owner: 'alice', data_class: 'confidential',
    }) }));
  expect(onSaved).not.toHaveBeenCalled();
});
it('keeps paths with spaces intact and releases saving state after a failure', async () => {
  await i18n.changeLanguage('en-US');
  const request = vi.spyOn(transport, 'callApi').mockRejectedValue(new Error('validation failed'));
  render(<SkillReviewModal skill={skill} mode="allowlist" canWrite onClose={vi.fn()} onSaved={vi.fn()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await screen.findByText('validation failed');
  await waitFor(() => expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled());
  expect(request).toHaveBeenCalledWith('/api/v1/skills/skill-one/whitelist', expect.any(Function),
    expect.objectContaining({ body: expect.objectContaining({ paths: ['C:\\Program Files\\Tools\\*'] }) }));
});
it('provides inspectable values while revoking all writes on permission loss', async () => {
  await i18n.changeLanguage('en-US');
  const request = vi.spyOn(transport, 'callApi');
  const view = render(<SkillReviewModal skill={skill} mode="allowlist" canWrite onClose={vi.fn()} onSaved={vi.fn()} />);
  view.rerender(<SkillReviewModal skill={skill} mode="allowlist" canWrite={false} onClose={vi.fn()} onSaved={vi.fn()} />);
  expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
  expect(screen.getByText('api.example.test')).toBeInTheDocument();
  expect(request).not.toHaveBeenCalled();
});

