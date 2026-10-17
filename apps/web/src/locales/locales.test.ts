import { describe, expect, it } from 'vitest';

import { enUS } from './en-US';
import { zhCN } from './zh-CN';

/**
 * Locale parity is a hard requirement: the UI defaults to zh-CN, and a key that
 * exists only in one file would silently render as its raw key in the other
 * language. This test fails loudly instead.
 */
describe('locale parity (zh-CN / en-US)', () => {
  it('has exactly the same translation keys in both locales', () => {
    const zhKeys = Object.keys(zhCN).sort();
    const enKeys = Object.keys(enUS).sort();

    const missingInEn = zhKeys.filter((key) => !enKeys.includes(key));
    const missingInZh = enKeys.filter((key) => !zhKeys.includes(key));

    expect(missingInEn, `missing in en-US: ${missingInEn.join(', ')}`).toEqual([]);
    expect(missingInZh, `missing in zh-CN: ${missingInZh.join(', ')}`).toEqual([]);
    expect(enKeys).toEqual(zhKeys);
  });

  it('has no empty translations', () => {
    const empty = [...Object.entries(zhCN), ...Object.entries(enUS)]
      .filter(([, value]) => String(value).trim() === '' && !String(value).includes('unit.'))
      .map(([key]) => key);
    // Intentional empties (unit suffixes that only exist in zh-CN) are allowed.
    const allowed = new Set(['unit.assets', 'unit.findings']);
    expect(empty.filter((key) => !allowed.has(key))).toEqual([]);
  });

  it('keeps every i18next placeholder consistent between locales', () => {
    const placeholders = (value: string): string[] =>
      (value.match(/\{\{\s*(\w+)[^}]*\}\}/g) ?? []).map((token) => token.replace(/[{}\s]/g, '')).sort();

    const mismatched: string[] = [];
    for (const [key, zhValue] of Object.entries(zhCN)) {
      const enValue = (enUS as Record<string, string>)[key];
      if (typeof enValue !== 'string') {
        continue;
      }
      if (placeholders(String(zhValue)).join(',') !== placeholders(enValue).join(',')) {
        mismatched.push(key);
      }
    }
    expect(mismatched, `placeholder mismatch: ${mismatched.join(', ')}`).toEqual([]);
  });

  it('covers every domain, severity and status enum used by the tables', () => {
    for (const domain of ['asset', 'data', 'identity', 'runtime', 'compliance']) {
      expect(zhCN).toHaveProperty(`domain.${domain}`);
      expect(enUS).toHaveProperty(`domain.${domain}`);
    }
    for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
      expect(zhCN).toHaveProperty(`severity.${severity}`);
      expect(enUS).toHaveProperty(`severity.${severity}`);
    }
    for (const status of ['open', 'acknowledged', 'in-progress', 'resolved', 'suppressed']) {
      expect(zhCN).toHaveProperty(`status.${status}`);
      expect(enUS).toHaveProperty(`status.${status}`);
    }
  });

  it('documents every route in the sidebar navigation', () => {
    const routes = [
      'nav.overview',
      'nav.assets',
      'nav.agents',
      'nav.mcps',
      'nav.skills',
      'nav.models',
      'nav.topology',
      'nav.findings',
      'nav.rules',
      'nav.redteam',
      'nav.policies',
      'nav.runtime',
      'nav.ingest',
      'nav.alerts',
      'nav.cases',
      'nav.integrations',
      'nav.alicloud',
      'nav.audit',
      'nav.reports',
      'nav.settings',
    ];
    for (const route of routes) {
      expect(zhCN).toHaveProperty(route);
      expect(enUS).toHaveProperty(route);
    }
  });
});
