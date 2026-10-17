import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import * as transport from '@/api/transport';
import i18n from '@/locales/i18n';
import type { AssetProfile } from '@/types/domain';
import { AssetGovernance } from './AssetGovernance';

describe('asset review', () => {
  it('retains the reviewed timestamp and draft after a conflicting update', async () => {
    await i18n.changeLanguage('en-US');
    const request = vi.spyOn(transport, 'callApi').mockRejectedValue(new transport.ApiRequestError('stale',409,'conflict'));
    const profile = {asset:{id:'asset-one'}, governance:{canWrite:true,lifecycle:'trial',allowedNext:['production'],
      updatedAt:'2026-09-21T10:00:00Z',owner:'alice',department:'Security',dataClass:'internal'},changes:[]} as unknown as AssetProfile;
    const onSaved=vi.fn();
    const rendered=render(<AssetGovernance profile={profile} onSaved={onSaved} onRemoved={onSaved}/>);
    fireEvent.click(screen.getByRole('button',{name:'Review lifecycle'}));
    fireEvent.change(screen.getByLabelText('Review note'),{target:{value:'Reviewed external access'}});
    rendered.rerender(<AssetGovernance profile={{...profile,governance:{...profile.governance!,updatedAt:'2026-09-21T10:01:00Z'}}} onSaved={onSaved} onRemoved={onSaved}/>);
    fireEvent.click(screen.getByRole('button',{name:'Save review'}));
    await waitFor(()=>expect(screen.getByText('This asset has changed. Review the latest values before saving again.')).toBeInTheDocument());
    expect(request).toHaveBeenCalledWith('/api/v1/assets/asset-one/transition',expect.any(Function),
      expect.objectContaining({body:expect.objectContaining({expected_updated_at:'2026-09-21T10:00:00Z',note:'Reviewed external access'})}));
    expect(screen.getByLabelText('Review note')).toHaveValue('Reviewed external access');
    expect(onSaved).not.toHaveBeenCalled();
    rendered.unmount();vi.restoreAllMocks();
    const readonly=render(<AssetGovernance profile={{...profile,governance:{...profile.governance!,canWrite:false}}} onSaved={onSaved} onRemoved={onSaved}/>);
    expect(screen.queryByRole('button',{name:'Review lifecycle'})).toBeNull();
    readonly.unmount();
  });
});
