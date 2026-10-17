import { describe, expect, it } from 'vitest';
import { composePolicyCode, validatePolicyCode } from './policyCode';
import { policyBody } from '@/api/payloads';

describe('executable policy editor contract', () => {
  it('uses actual context fields, backend actions and escaped literals', () => {
    const code = composePolicyCode('cel', 'mask', [{ id: '1', field: 'request.host', operator: 'contains', value: 'a"b\\c' }]);
    expect(code).toContain('input.domain.contains("a\\"b\\\\c")');
    expect(code).toContain('"action":"redact"');
    expect(code).not.toContain('decision :=');
    expect(validatePolicyCode(code, 'cel').ok).toBe(true);
  });
  it('generates the required Rego package and action rule without a catch-all allow', () => {
    const code=composePolicyCode('rego','deny',[{id:'1',field:'request.command',operator:'matches',value:'danger.*'}]);
    expect(code).toContain('package agf\n');
    expect(code).toContain('regex.match("danger.*", input.command)');
    expect(code).toContain('action := "deny" if {');
    expect(code).not.toContain('default');
    expect(validatePolicyCode(code,'rego').ok).toBe(true);
    expect(validatePolicyCode('package agf.generated\ndecision := true','rego').ok).toBe(false);
  });
  it('preserves structured edits and rejects empty form conditions', () => {
    expect(policyBody({codeLanguage:'structured',code:'{"commandDeny":["danger"]}',action:'quarantine'}))
      .toMatchObject({language:'structured',structured:{command_deny:['danger']},action:'isolate'});
    expect(()=>composePolicyCode('cel','deny',[{id:'1',field:'request.host',operator:'contains',value:''}])).toThrow();
  });
  it('generates the exact quota, approval and canonical circuit-break verbs and rejects unknown actions', () => {
    for (const action of ['quota', 'approval', 'circuit-break'] as const) {
      expect(composePolicyCode('cel', action, [])).toContain(`"action":"${action}"`);
      expect(policyBody({ action, codeLanguage: 'cel', code: composePolicyCode('cel', action, []) })).toMatchObject({ action });
    }
    expect(() => composePolicyCode('cel', 'unknown', [])).toThrow(/Unknown policy action/);
  });
});
