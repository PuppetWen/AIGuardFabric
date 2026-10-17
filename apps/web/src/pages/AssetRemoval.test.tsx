import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import * as transport from '@/api/transport';
import i18n from '@/locales/i18n';
import type { AssetProfile } from '@/types/domain';
import { AssetRemoval } from './AssetRemoval';

describe('asset removal', () => {
  it('requires a terminal state and the current asset name before sending the versioned removal', async () => {
    await i18n.changeLanguage('en-US');
    const request = vi.spyOn(transport, 'callApi').mockResolvedValue({ data: null } as never);
    const onRemoved = vi.fn().mockResolvedValue(undefined);
    const profile = { asset: { id: 'asset-one', name: 'Retired skill' },
      governance: { canWrite: true, lifecycle: 'archived', updatedAt: '2026-09-27T10:00:00Z' } } as AssetProfile;
    const view = render(<AssetRemoval profile={profile} onRemoved={onRemoved} />);
    fireEvent.click(screen.getByRole('button', { name: 'Remove from current inventory' }));
    expect(screen.getByText(/reappears if a source reports the same fingerprint/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Type the asset name to confirm'), { target: { value: 'Other skill' } });
    fireEvent.change(screen.getByLabelText('Reason (recorded in audit)'), { target: { value: 'Retired service' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm removal' }));
    await screen.findByText('Name does not match this asset');
    expect(request).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('Type the asset name to confirm'), { target: { value: 'Retired skill' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm removal' }));
    await waitFor(() => expect(onRemoved).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith('/api/v1/assets/asset-one', expect.any(Function),
      expect.objectContaining({ method: 'DELETE', noFallback: true, body: {
        expected_updated_at: '2026-09-27T10:00:00Z', confirm_name: 'Retired skill', reason: 'Retired service',
      } }));
    view.unmount(); vi.restoreAllMocks();
    const active = render(<AssetRemoval profile={{ ...profile,
      governance: { ...profile.governance!, lifecycle: 'trial' } }} onRemoved={onRemoved} />);
    expect(screen.queryByRole('button', { name: 'Remove from current inventory' })).toBeNull();
    active.unmount();
  });
});
