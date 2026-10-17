import { describe, expect, it } from 'vitest';

import type { PolicyAction, QuotaUsage } from '@/types/domain';

import { DOMAIN_HEX, HEALTH_HEX, POLICY_ACTION_HEX } from './palette';
import { SEVERITY_ORDER, SEVERITY_STYLE, severityColor, severityKey, severityWeight } from './severity';
import { contrastOverTranslucent, contrastRatio, hexToRgb, round2 } from './colors';
import { policyActionKey, quotaLevelKey, quotaRatio } from './labels';
import { enUS } from '@/locales/en-US';
import { zhCN } from '@/locales/zh-CN';

/** Surfaces the chips are actually painted on (see styles/global.css). */
const DARK_SURFACE = '#131b29';
const DARK_ELEVATED = '#182233';

describe('severity mapping', () => {
  it('orders severities from most to least severe', () => {
    expect(SEVERITY_ORDER).toEqual(['critical', 'high', 'medium', 'low', 'info']);
    expect(severityWeight('critical')).toBeGreaterThan(severityWeight('high'));
    expect(severityWeight('high')).toBeGreaterThan(severityWeight('medium'));
    expect(severityWeight('medium')).toBeGreaterThan(severityWeight('low'));
    expect(severityWeight('low')).toBeGreaterThan(severityWeight('info'));
  });

  it('exposes a distinct colour per severity and per theme', () => {
    const hexes = SEVERITY_ORDER.map((severity) => SEVERITY_STYLE[severity].hex);
    expect(new Set(hexes).size).toBe(SEVERITY_ORDER.length);

    for (const severity of SEVERITY_ORDER) {
      expect(severityColor(severity, 'dark')).toBe(SEVERITY_STYLE[severity].dark);
      expect(severityColor(severity, 'light')).toBe(SEVERITY_STYLE[severity].light);
    }
  });

  it('maps every severity to an i18n key present in both locales', () => {
    for (const severity of SEVERITY_ORDER) {
      expect(zhCN).toHaveProperty(severityKey(severity));
      expect(enUS).toHaveProperty(severityKey(severity));
    }
  });

  it('keeps severity chip text readable on the dark panel', () => {
    for (const severity of SEVERITY_ORDER) {
      const style = SEVERITY_STYLE[severity];
      const ratio = contrastOverTranslucent(style.dark, style.bg, DARK_SURFACE);
      expect(round2(ratio), `${severity} chip ${style.dark} on ${style.bg}`).toBeGreaterThanOrEqual(4.5);
    }
  });
});

describe('policy action labels', () => {
  const actions: PolicyAction[] = ['allow', 'deny', 'alert', 'mask', 'redirect', 'throttle', 'quota',
    'quarantine', 'approval', 'circuit-break', 'unknown'];

  it('has a label key and a colour for every action', () => {
    for (const action of actions) {
      const key = policyActionKey(action);
      expect(zhCN, key).toHaveProperty(key);
      expect(enUS, key).toHaveProperty(key);
      expect(POLICY_ACTION_HEX[action]).toMatch(/^#[0-9a-f]{6}$/i);
    }
  });

  it('gives allow and deny visually opposite colours', () => {
    expect(POLICY_ACTION_HEX.allow).not.toBe(POLICY_ACTION_HEX.deny);
    const allowLuminance = contrastRatio(POLICY_ACTION_HEX.allow, DARK_SURFACE);
    const denyLuminance = contrastRatio(POLICY_ACTION_HEX.deny, DARK_SURFACE);
    expect(allowLuminance).toBeGreaterThan(3);
    expect(denyLuminance).toBeGreaterThan(3);
  });
});

describe('quota usage ratio', () => {
  const base: QuotaUsage = {
    scope: 'tenant',
    scopeId: 'ten-acme',
    scopeName: 'Acme',
    unit: 'tokens',
    used: 0,
    limit: 100,
    windowStart: '2025-03-18T00:00:00.000Z',
    windowEnd: '2025-03-19T00:00:00.000Z',
    throttled: false,
  };

  it('reports normal usage below 80%', () => {
    const ratio = quotaRatio({ used: 50, limit: 100 });
    expect(ratio.ratio).toBe(0.5);
    expect(ratio.percent).toBe(50);
    expect(ratio.level).toBe('normal');
    expect(quotaLevelKey(ratio.level)).toBe('runtime.quota.normal');
  });

  it('warns between 80% and 100%', () => {
    const ratio = quotaRatio({ used: 85, limit: 100 });
    expect(ratio.level).toBe('warning');
    expect(ratio.clampedRatio).toBeCloseTo(0.85, 5);
  });

  it('flags exceeded usage and clamps the bar ratio', () => {
    const ratio = quotaRatio({ used: 118, limit: 100 });
    expect(ratio.level).toBe('exceeded');
    expect(ratio.ratio).toBeCloseTo(1.18, 5);
    expect(ratio.percent).toBe(118);
    expect(ratio.clampedRatio).toBe(1);
  });

  it('treats a zero or missing limit as no quota rather than dividing by zero', () => {
    expect(quotaRatio({ used: 10, limit: 0 })).toEqual({
      ratio: 0,
      percent: 0,
      clampedRatio: 0,
      level: 'normal',
    });
    expect(quotaRatio({ used: 10, limit: Number.NaN }).ratio).toBe(0);
    expect(quotaRatio({ used: -5, limit: 100 }).ratio).toBe(0);
  });

  it('matches the demo dataset expectations', () => {
    expect(quotaRatio({ ...base, used: 99, limit: 100 }).level).toBe('warning');
    expect(quotaRatio({ ...base, used: 100, limit: 100 }).level).toBe('exceeded');
  });
});

describe('dark theme contrast (WCAG AA)', () => {
  const bodyText = '#e8edf6';
  const secondaryText = '#a7b3c7';
  const tertiaryText = '#8593a8';

  it('body text clears 4.5:1 on both panel surfaces', () => {
    expect(round2(contrastRatio(bodyText, DARK_SURFACE))).toBeGreaterThanOrEqual(4.5);
    expect(round2(contrastRatio(bodyText, DARK_ELEVATED))).toBeGreaterThanOrEqual(4.5);
  });

  it('secondary text clears 4.5:1 and tertiary clears 3:1', () => {
    expect(round2(contrastRatio(secondaryText, DARK_SURFACE))).toBeGreaterThanOrEqual(4.5);
    expect(round2(contrastRatio(tertiaryText, DARK_SURFACE))).toBeGreaterThanOrEqual(3);
  });

  it('domain and health accents stay legible as chart/text colours', () => {
    for (const [name, hex] of Object.entries({ ...DOMAIN_HEX, ...HEALTH_HEX })) {
      expect(round2(contrastRatio(hex, DARK_SURFACE)), `${name} ${hex}`).toBeGreaterThanOrEqual(3);
    }
  });

  it('parses hex colours correctly', () => {
    expect(hexToRgb('#ffffff')).toEqual({ r: 255, g: 255, b: 255 });
    expect(hexToRgb('#000')).toEqual({ r: 0, g: 0, b: 0 });
    expect(contrastRatio('#ffffff', '#000000')).toBeCloseTo(21, 1);
  });
});
