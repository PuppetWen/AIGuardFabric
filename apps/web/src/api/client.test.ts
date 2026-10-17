import { beforeEach, describe, expect, it, vi } from 'vitest';

import { __resetDataSource, api, camelizeDeep, getDataSourceSnapshot, isDemoMode, adaptLoginResponse } from '@/api/client';
import { demoAssets, demoFindings, demoRules } from '@/api/demo';
import { buildRuleTestResult } from '@/api/demo/detection';
import type { AuditEntry } from '@/types/domain';
import { verifyAuditChain, chainHash, auditPayload } from '@/api/demo/audit';
import { renderMarkdown } from '@/utils/markdown';
import { countdown } from '@/utils/format';

/**
 * The offline fallback is the single most important behaviour of this app: with
 * no backend running, every page must still render. These tests pin that down.
 */
describe('api client demo fallback', () => {
  beforeEach(() => {
    __resetDataSource();
    vi.restoreAllMocks();
  });

  it('falls back to the built-in dataset when fetch rejects (network error)', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))),
    );

    const result = await api.assets({}, { pageSize: 5 });

    expect(result.meta.source).toBe('demo');
    expect(result.data.total).toBeGreaterThan(0);
    expect(result.data.items.length).toBeGreaterThan(0);
    expect(isDemoMode()).toBe(true);
    expect(getDataSourceSnapshot().source).toBe('demo');
    expect(getDataSourceSnapshot().reason).toBeTruthy();
  });

  it('falls back when the backend returns a 5xx response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          new Response('gateway down', { status: 503, headers: { 'Content-Type': 'text/plain' } }),
        ),
      ),
    );

    const result = await api.overview();

    expect(result.meta.source).toBe('demo');
    expect(result.data.kpis).toHaveLength(5);
    expect(result.data.domainDistribution).toHaveLength(5);
  });

  it('falls back on a non-JSON body (e.g. an HTML error page from a proxy)', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          new Response('<html>502 Bad Gateway</html>', {
            status: 200,
            headers: { 'Content-Type': 'text/html' },
          }),
        ),
      ),
    );

    const result = await api.findings();
    expect(result.meta.source).toBe('demo');
    expect(result.data.items.length).toBeGreaterThan(0);
  });

  it('uses live data and clears the demo flag when the backend answers', async () => {
    const payload = {
      items: [demoAssets[0]],
      total: 1,
      page: 1,
      pageSize: 10,
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          new Response(JSON.stringify(payload), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        ),
      ),
    );

    const result = await api.assets();

    expect(result.meta.source).toBe('live');
    expect(result.data.total).toBe(1);
    expect(isDemoMode()).toBe(false);
    expect(getDataSourceSnapshot().source).toBe('live');
  });

  it('keeps enough demo fixtures for every page to look real', () => {
    expect(demoAssets.length).toBeGreaterThanOrEqual(30);
    expect(demoFindings.length).toBeGreaterThanOrEqual(12);
    expect(demoRules.length).toBeGreaterThanOrEqual(12);
    // Every finding must point at a rule that actually exists.
    const ruleIds = new Set(demoRules.map((rule) => rule.id));
    for (const finding of demoFindings) {
      expect(ruleIds.has(finding.ruleId)).toBe(true);
    }
  });

  it('never replaces a failed login with a local demo session', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))),
    );

    await expect(api.login({
      tenantSlug: 'acme',
      username: 'admin',
      password: 'Admin@12345',
      mfaCode: '123456',
    })).rejects.toThrow('Network error');
  });
});

describe('live backend contract adaptation', () => {
  // 下面两段 JSON 是**本机真实后端**的响应原文（compose 栈 agf-server 0.1.0），
  // 不是手写的理想形状——契约适配就是冲着它们来的。
  const REAL_FIRST_LOGIN = `{
    "must_change_password": true,
    "change_token": "eyJhbGciOiJIUzI1NiJ9.first-login-token",
    "user": {
      "id": "01a0af79-d68b-7520-8ff3-dfcf150a58d3",
      "tenant_id": "00000000-0000-0000-0000-000000000001",
      "username": "admin",
      "email": "admin@aiguardfabric.local",
      "display_name": "admin",
      "state": "active",
      "is_superadmin": true,
      "must_change_password": true,
      "mfa_enabled": false,
      "last_login_at": "2026-09-17T13:07:28.199000205Z"
    },
    "permissions": []
  }`;

  const REAL_SESSION_LOGIN = `{
    "must_change_password": false,
    "tokens": { "access_token": "eyJhbGciOiJIUzI1NiJ9.session", "refresh_token": "refresh-1" },
    "user": {
      "id": "01a0af79-d68b-7520-8ff3-dfcf150a58d3",
      "tenant_id": "00000000-0000-0000-0000-000000000001",
      "username": "admin",
      "display_name": "admin",
      "state": "active",
      "is_superadmin": true,
      "roles": ["superadmin"],
      "mfa_enabled": false
    }
  }`;

  it('转换 snake_case 分页信封与实体字段（否则页面读不到 pageSize / riskScore）', () => {
    const raw = JSON.parse(
      '{"items":[{"id":"a1","risk_score":92,"last_seen_at":"2026-09-17T00:00:00Z"}],"total":1,"page":1,"page_size":20,"has_more":false,"next_cursor":null}',
    );
    const value = camelizeDeep(raw) as {
      pageSize: number;
      hasMore: boolean;
      items: Array<Record<string, unknown>>;
    };
    expect(value.pageSize).toBe(20);
    expect(value.hasMore).toBe(false);
    expect(value.items[0]?.riskScore).toBe(92);
    expect(value.items[0]?.lastSeenAt).toBe('2026-09-17T00:00:00Z');
  });

  it('首登响应整形为 change_token + mustChangePassword=true（不发会话令牌）', () => {
    const data = adaptLoginResponse(JSON.parse(REAL_FIRST_LOGIN) as never, {
      tenantSlug: 'default',
      username: 'admin',
      password: 'x',
    });
    expect(data.mustChangePassword).toBe(true);
    expect(data.token).toBe('eyJhbGciOiJIUzI1NiJ9.first-login-token');
    expect(data.user.displayName).toBe('admin');
    expect(data.user.role).toBe('owner');
    expect(data.user.status).toBe('active');
    expect(data.tenant.slug).toBe('default');
  });

  it('改密后的会话响应整形为 access_token 且不再要求改密', () => {
    const data = adaptLoginResponse(JSON.parse(REAL_SESSION_LOGIN) as never, {
      tenantSlug: 'default',
      username: 'admin',
      password: 'x',
    });
    expect(data.mustChangePassword).toBe(false);
    expect(data.token).toBe('eyJhbGciOiJIUzI1NiJ9.session');
    expect(data.user.role).toBe('owner');
  });

  it('角色映射覆盖平台角色名', () => {
    const asRole = (roles: string[], superadmin = false): string =>
      adaptLoginResponse(
        { mustChangePassword: false, tokens: { accessToken: 't' }, user: { roles, isSuperadmin: superadmin } } as never,
        { tenantSlug: 'default', username: 'u', password: 'x' },
      ).user.role;
    expect(asRole(['tenant-admin'])).toBe('admin');
    expect(asRole(['soc-analyst'])).toBe('analyst');
    expect(asRole(['redteam-engineer'])).toBe('responder');
    expect(asRole(['auditor'])).toBe('auditor');
    expect(asRole([], true)).toBe('owner');
    expect(asRole(['unknown-role'])).toBe('viewer');
  });
});

describe('rule regression samples', () => {
  it('counts each confusion-matrix cell from the sample list', () => {
    const result = buildRuleTestResult('RULE-RT-001');
    const positives = result.samples.filter((sample) => sample.label === 'positive');
    const negatives = result.samples.filter((sample) => sample.label === 'negative');

    expect(result.truePositive).toBe(positives.filter((sample) => sample.matched).length);
    expect(result.falseNegative).toBe(positives.filter((sample) => !sample.matched).length);
    expect(result.trueNegative).toBe(negatives.filter((sample) => !sample.matched).length);
    expect(result.falsePositive).toBe(negatives.filter((sample) => sample.matched).length);
    expect(result.samples.length).toBeGreaterThanOrEqual(5);
  });
});

describe('audit hash chain', () => {
  it('detects the seeded tampered entry and reports a partial verdict', () => {
    const result = verifyAuditChain();
    expect(result.checkedEntries).toBeGreaterThan(5);
    expect(result.verdict).toBe('partial');
    expect(result.issues.length).toBeGreaterThanOrEqual(1);
    expect(result.issues[0]?.reason).toContain('哈希');
  });

  it('verifies a hand-built, untouched single-entry chain as valid', () => {
    const base: Omit<AuditEntry, 'hash' | 'prevHash'> = {
      id: 'AUD-1',
      ts: '2025-03-18T09:00:00.000Z',
      actor: 'a',
      actorRole: 'admin',
      action: 'x',
      sensitive: false,
      resourceKind: 'policy',
      resourceId: 'r1',
      resourceName: 'n',
      result: 'success',
      ip: '10.0.0.1',
      userAgent: 'ua',
      detail: 'd',
    };
    const genesis = 'sha256:00000000000000000000000000000000';
    const entry: AuditEntry = { ...base, prevHash: genesis, hash: chainHash(genesis, auditPayload(base)) };

    const check = verifyAuditChain([entry]);

    expect(check.verdict).toBe('valid');
    expect(check.issues).toHaveLength(0);
    expect(check.checkedEntries).toBe(1);
  });
});

describe('markdown report renderer', () => {
  it('renders headings, code fences and tables', () => {
    const html = renderMarkdown(
      ['# Title', '', '| a | b |', '| --- | --- |', '| 1 | 2 |', '', '```', 'raw <tag>', '```'].join('\n'),
    );
    expect(html).toContain('<h1>Title</h1>');
    expect(html).toContain('<table>');
    expect(html).toContain('&lt;tag&gt;');
  });

  it('escapes HTML so a report body cannot inject markup', () => {
    const html = renderMarkdown('<script>alert(1)</script>');
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });
});

describe('SLA countdown', () => {
  it('flags a breached SLA with a negative sign', () => {
    const past = countdown('2025-03-18T09:00:00.000Z', Date.parse('2025-03-18T09:30:00.000Z'));
    expect(past.breached).toBe(true);
    expect(past.text.startsWith('-')).toBe(true);
  });

  it('renders a remaining SLA as a clock', () => {
    const future = countdown('2025-03-18T10:00:00.000Z', Date.parse('2025-03-18T09:30:00.000Z'));
    expect(future.breached).toBe(false);
    expect(future.text).toBe('00:30:00');
  });
});
