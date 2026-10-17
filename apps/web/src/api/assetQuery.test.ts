import { describe, expect, it } from 'vitest';
import { assetQuery } from './assetQuery';

describe('asset server filters', () => {
  it('preserves every selection and server sorting without repeated query keys', () => {
    expect(assetQuery({kinds:['mcp','skill'],departments:['Security Ops','Platform'],classifications:['internal','restricted'],
      lifecycles:['active','onboarding'],exposures:['intranet','partner'],keyword:'alice'},
    {page:2,pageSize:10,sortBy:'riskScore',sortOrder:'desc'})).toEqual({kinds:'mcp,skill',departments:'Security Ops,Platform',
      classifications:'internal,restricted',lifecycles:'active,onboarding',exposures:'intranet,partner',keyword:'alice',page:2,pageSize:10,sortBy:'riskScore',sortOrder:'desc'});
  });
});
