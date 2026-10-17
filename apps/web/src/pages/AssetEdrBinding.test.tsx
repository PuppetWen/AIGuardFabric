import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import * as transport from '@/api/transport';
import i18n from '@/locales/i18n';
import type { AssetProfile } from '@/types/domain';
import { AssetEdrBinding } from './AssetEdrBinding';

describe('EDR host binding for existing assets', () => {
  it('submits the reviewed asset revision and never uses a demo fallback', async () => {
    await i18n.changeLanguage('en-US');
    const request = vi.spyOn(transport, 'callApi').mockResolvedValue({ data: {}, meta: { source: 'live', elapsedMs: 1, at: Date.now() } });
    const onSaved = vi.fn().mockResolvedValue(undefined);
    const profile = { asset: { id: 'asset-one', edrHostId: '' },
      governance: { canWrite: true, updatedAt: '2026-09-23T12:00:00Z' } } as unknown as AssetProfile;
    const rendered = render(<AssetEdrBinding profile={profile} onSaved={onSaved} />);
    fireEvent.click(screen.getByRole('button', { name: 'Bind or change EDR host' }));
    fireEvent.change(screen.getByLabelText('Remote host ID'), { target: { value: 'host-42' } });
    fireEvent.change(screen.getByLabelText('Reason for change'), { target: { value: 'Verified in EDR' } });
    fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    await waitFor(() => expect(request).toHaveBeenCalledWith('/api/v1/assets/asset-one/edr-host', expect.any(Function),
      expect.objectContaining({ method: 'PUT', noFallback: true,
        body: { host_id: 'host-42', expected_updated_at: '2026-09-23T12:00:00Z', reason: 'Verified in EDR' } })));
    await waitFor(() => expect(onSaved).toHaveBeenCalledOnce());
    rendered.unmount(); request.mockRestore();
  });
});
