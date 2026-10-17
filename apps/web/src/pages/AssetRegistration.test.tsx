import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import * as transport from '@/api/transport';
import i18n from '@/locales/i18n';
import { AssetRegistration } from './AssetRegistration';
import { AssetGovernance } from './AssetGovernance';
import type { AssetProfile } from '@/types/domain';

describe('manual asset application', () => {
  it('review labels target the visible form after closing registration', async () => {
    await i18n.changeLanguage('en-US');
    const profile = { asset: { id: 'reviewed' }, governance: { canWrite: true, lifecycle: 'requested',
      allowedNext: ['under-review'], updatedAt: '2026-09-21T10:00:00Z', owner: 'existing owner', dataClass: 'internal' } } as AssetProfile;
    const saved = vi.fn().mockResolvedValue(undefined);
    const rendered = render(<><AssetRegistration onSaved={saved} /><AssetGovernance profile={profile} onSaved={saved} onRemoved={saved} /></>);
    fireEvent.click(screen.getByRole('button', { name: 'Register asset' }));
    fireEvent.change(screen.getByLabelText('Application purpose'), { target: { value: 'Registration draft' } });
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    fireEvent.click(screen.getByRole('button', { name: 'Review lifecycle' }));
    const note = await screen.findByLabelText('Review note');
    expect(note).toHaveValue('');
    const review = within(note.closest('form')!);
    expect(review.getByLabelText('Owner')).toHaveValue('existing owner');
    rendered.unmount();
  });
  it('keeps the request ID and input across an uncertain network result', async () => {
    await i18n.changeLanguage('en-US');
    const request = vi.spyOn(transport, 'callApi').mockRejectedValueOnce(new Error('Connection lost'))
      .mockResolvedValueOnce({ data: { asset: { id: 'registered' } }, meta: { source: 'live' } } as never);
    const saved = vi.fn().mockResolvedValue(undefined);
    const rendered = render(<AssetRegistration onSaved={saved} />);
    fireEvent.click(screen.getByRole('button', { name: 'Register asset' }));
    for (const [label, value] of [['Asset name', 'Finance agent'], ['Unique inventory key', 'finance/agent'],
      ['Owner', 'alice'], ['Application purpose', 'Review expense reports']]) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    fireEvent.click(screen.getByRole('button', { name: 'Submit application' }));
    await waitFor(() => expect(screen.getByText('Connection lost')).toBeInTheDocument());
    expect(screen.getByLabelText('Asset name')).toHaveValue('Finance agent');
    const first = request.mock.calls[0][2]?.body;
    fireEvent.click(screen.getByRole('button', { name: 'Submit application' }));
    await waitFor(() => expect(saved).toHaveBeenCalledWith('registered'));
    expect(request.mock.calls[1][2]?.body).toEqual(first);
    expect(first).toMatchObject({ data_class: 'internal', request_id: expect.any(String), fingerprint: 'finance/agent' });
    rendered.unmount(); vi.restoreAllMocks();
  });
});
