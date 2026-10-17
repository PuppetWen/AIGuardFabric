import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import * as transport from '@/api/transport';
import i18n from '@/locales/i18n';
import type { AssetProfile } from '@/types/domain';
import { AssetMetadataEditor } from './AssetMetadataEditor';

describe('asset metadata correction', () => {
  it('submits the reviewed asset revision and explains inventory-only effects', async () => {
    await i18n.changeLanguage('en-US');
    const request = vi.spyOn(transport, 'callApi').mockResolvedValue({ data: null } as never);
    const onSaved = vi.fn().mockResolvedValue(undefined);
    const profile = { asset: { id: 'asset-one', name: 'Original name' },
      governance: { canWrite: true, updatedAt: '2026-09-27T10:00:00Z', owner: 'alice',
        department: 'Finance', dataClass: 'internal' } } as unknown as AssetProfile;
    const view = render(<AssetMetadataEditor profile={profile} onSaved={onSaved} />);
    fireEvent.click(screen.getByRole('button', { name: 'Edit asset details' }));
    expect(screen.getByText(/does not change an external Agent or endpoint/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Owner'), { target: { value: 'bob' } });
    fireEvent.change(screen.getByLabelText('Reason (recorded in change history)'),
      { target: { value: 'Annual review' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(onSaved).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith('/api/v1/assets/asset-one', expect.any(Function),
      expect.objectContaining({ method: 'PATCH', noFallback: true, body: expect.objectContaining({
        name: 'Original name', owner: 'bob', department: 'Finance', data_class: 'internal',
        expected_updated_at: '2026-09-27T10:00:00Z', reason: 'Annual review',
      }) }));
    view.unmount(); vi.restoreAllMocks();
    const readonly = render(<AssetMetadataEditor profile={{ ...profile,
      governance: { ...profile.governance!, canWrite: false } }} onSaved={onSaved} />);
    expect(screen.queryByRole('button', { name: 'Edit asset details' })).toBeNull();
    readonly.unmount();
  });
});
