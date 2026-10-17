import type { Policy } from '@/types/domain';

export function policyFixture(version = 1, overrides: Partial<Policy> = {}): Policy {
  return { id: '00000000-0000-4000-8000-000000000051', version, name: 'Owned policy', description: 'Server description',
    action: 'deny', priority: 50, lifecycle: 'enforced', interceptPoints: ['mcp-proxy'], expression: '',
    code: 'input.tool_name == "server" ? {"action":"deny"} : {}', codeLanguage: 'cel', enabled: true, dryRun: false,
    hitCount24h: 0, blockedCount24h: 0, signature: { status: 'signed', signer: '', keyId: '', digest: '', signedAt: null },
    updatedAt: '2026-10-01T00:00:00Z', author: 'test', ...overrides };
}
export function policyResult<T>(data: T) { return { data, meta: { source: 'live' as const, elapsedMs: 1, at: Date.now() } }; }
export function policyDeferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(accept => { resolve = accept; });
  return { promise, resolve };
}
