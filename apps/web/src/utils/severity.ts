import type { Severity } from '@/types/domain';

/**
 * Severity presentation. `dark` / `light` carry AA-contrast foreground colours
 * (verified by `colors.test.ts`), `bg`/`border` are the translucent chip colours
 * used inside tables, and `hex` feeds the charts and the G6 topology palette.
 */
export interface SeverityStyle {
  hex: string;
  dark: string;
  light: string;
  bg: string;
  border: string;
  /** antd Tag colour token. */
  tag: string;
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_STYLE: Record<Severity, SeverityStyle> = {
  critical: {
    hex: '#e5484d',
    dark: '#ff8b90',
    light: '#a8071a',
    bg: 'rgba(229, 72, 77, 0.16)',
    border: 'rgba(229, 72, 77, 0.45)',
    tag: 'red',
  },
  high: {
    hex: '#f26b2c',
    dark: '#ffab7a',
    light: '#ad3a00',
    bg: 'rgba(242, 107, 44, 0.16)',
    border: 'rgba(242, 107, 44, 0.45)',
    tag: 'orange',
  },
  medium: {
    hex: '#d9a326',
    dark: '#f0cc6a',
    light: '#8a6100',
    bg: 'rgba(217, 163, 38, 0.16)',
    border: 'rgba(217, 163, 38, 0.45)',
    tag: 'gold',
  },
  low: {
    hex: '#3d8bfd',
    dark: '#8fbaff',
    light: '#0b4ea2',
    bg: 'rgba(61, 139, 253, 0.16)',
    border: 'rgba(61, 139, 253, 0.45)',
    tag: 'blue',
  },
  info: {
    hex: '#6f7683',
    dark: '#b0b8c4',
    light: '#4a5058',
    bg: 'rgba(111, 118, 131, 0.16)',
    border: 'rgba(111, 118, 131, 0.45)',
    tag: 'default',
  },
};

/** Colour for a severity, resolved for the active theme. */
export function severityColor(severity: Severity, theme: 'dark' | 'light' = 'dark'): string {
  const style = SEVERITY_STYLE[severity];
  return theme === 'dark' ? style.dark : style.light;
}

/** Sort weight — higher means more severe. */
export function severityWeight(severity: Severity): number {
  return SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(severity);
}

/** i18n key for a severity label. */
export function severityKey(severity: Severity): string {
  return `severity.${severity}`;
}
