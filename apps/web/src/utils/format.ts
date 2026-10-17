import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import utc from 'dayjs/plugin/utc';
import 'dayjs/locale/zh-cn';
import 'dayjs/locale/en';

dayjs.extend(relativeTime);
dayjs.extend(utc);

export type AppLocale = 'zh-CN' | 'en-US';

/** Missing server measurements must not be displayed as zero. */
export function formatNumber(value: number | null | undefined): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toLocaleString() : '—';
}

const DAYJS_LOCALE: Record<AppLocale, string> = {
  'zh-CN': 'zh-cn',
  'en-US': 'en',
};

/** Format an ISO timestamp for tables and drawers. */
export function formatDateTime(iso: string, locale: AppLocale = 'zh-CN'): string {
  if (!iso || !dayjs(iso).isValid()) return '—';
  return dayjs(iso).locale(DAYJS_LOCALE[locale]).format('YYYY-MM-DD HH:mm:ss');
}

/** Format an ISO timestamp without seconds (dense tables). */
export function formatShortDateTime(iso: string, locale: AppLocale = 'zh-CN'): string {
  if (!iso || !dayjs(iso).isValid()) return '—';
  return dayjs(iso).locale(DAYJS_LOCALE[locale]).format('MM-DD HH:mm');
}

/** Format an ISO timestamp as a chart axis label. */
export function formatDay(iso: string): string {
  if (!iso || !dayjs(iso).isValid()) return '—';
  return dayjs(iso).format('MM-DD');
}

/** Relative "x minutes ago" text. */
export function fromNow(iso: string, locale: AppLocale = 'zh-CN'): string {
  if (!iso || !dayjs(iso).isValid()) return '—';
  return dayjs(iso).locale(DAYJS_LOCALE[locale]).fromNow();
}

/** Compact number formatting: 1234 → 1.2K, 1_200_000 → 1.2M. */
export function compactNumber(value: number): string {
  if (!Number.isFinite(value)) {
    return '—';
  }
  const abs = Math.abs(value);
  if (abs >= 1_000_000_000) {
    return `${(value / 1_000_000_000).toFixed(1)}B`;
  }
  if (abs >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(1)}M`;
  }
  if (abs >= 1_000) {
    return `${(value / 1_000).toFixed(1)}K`;
  }
  return String(Math.round(value * 100) / 100);
}

/** Percentage with one decimal. */
export function formatPercent(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—';
  return `${Math.round(value * 1000) / 10}%`;
}

/** USD amount, two decimals. */
export function formatUsd(value: number): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—';
  return `$${value.toFixed(2)}`;
}

/** CNY amount, two decimals. */
export function formatCny(value: number, precision: 2 | 6 = 2): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—';
  return `¥${value.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: precision, useGrouping: false })}`;
}

/**
 * Countdown between two instants, split into sign + parts. Negative `totalMs`
 * means the SLA target has already passed.
 */
export interface Countdown {
  totalMs: number;
  breached: boolean;
  days: number;
  hours: number;
  minutes: number;
  seconds: number;
  /** `2d 04h`, `04:12:33`, or `breached 00:31:20`. */
  text: string;
}

export function countdown(targetIso: string, now: number = Date.now()): Countdown {
  const totalMs = dayjs(targetIso).valueOf() - now;
  const breached = totalMs < 0;
  const abs = Math.abs(totalMs);
  const days = Math.floor(abs / 86_400_000);
  const hours = Math.floor((abs % 86_400_000) / 3_600_000);
  const minutes = Math.floor((abs % 3_600_000) / 60_000);
  const seconds = Math.floor((abs % 60_000) / 1000);
  const clock = `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(
    seconds,
  ).padStart(2, '0')}`;
  const text = days > 0 ? `${days}d ${String(hours).padStart(2, '0')}h` : clock;
  return { totalMs, breached, days, hours, minutes, seconds, text: breached ? `-${text}` : text };
}

/** Truncate long payloads for table cells. */
export function truncate(value: string, max = 60): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

export { dayjs };
