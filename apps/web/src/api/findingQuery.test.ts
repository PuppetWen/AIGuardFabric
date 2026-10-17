import { describe, expect, it } from 'vitest';
import { findingQuery } from './findingQuery';
import { adaptResponse } from './adapters';
import { camelizeDeep } from './contract';

describe('finding filters and event evidence', () => {
  it('keeps multiple severities and maps all members of the selected display domains', () => {
    expect(findingQuery({ severity: ['high', 'low'], domain: ['runtime', 'identity'], status: ['pending', 'verified'] }, { page: 2 }))
      .toEqual({ page: 2, severity: 'high,low', domain: 'prompt-attack,tool-abuse,credential-leak', state: 'pending,verified' });
  });
  it('preserves event references and hashes without presenting them as an asset', () => {
    const result = adaptResponse('/api/v1/findings/id', camelizeDeep({ finding: {
      id: 'finding', target: 'event:tenant:event', evidence: [{ code: 'EV-EVENT', kind: 'event', content_hash: 'abc', artifact_ref: 'event:tenant:event' }],
    } }));
    expect(result).toMatchObject({ assetName: '—', evidence: [{ kind: 'event', contentHash: 'abc', artifactRef: 'event:tenant:event' }] });
  });
  it('does not present a scan label as an asset name', () => {
    const response = (raw: object) => adaptResponse('/api/v1/findings/id', camelizeDeep({ finding: raw }));
    expect(response({ target: 'scan-label' })).toMatchObject({ assetName: '—' });
    expect(response({ target: 'scan-label', asset_id: 'asset-id' })).toMatchObject({ assetName: 'asset-id' });
    expect(response({ target: 'scan-label', asset_id: 'asset-id', asset_name: 'Registered asset' }))
      .toMatchObject({ assetName: 'Registered asset' });
  });
});
