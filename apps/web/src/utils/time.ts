/**
 * Deterministic clock for the built-in demo dataset.
 *
 * Demo data must not depend on `Date.now()` at import time: the pages, the charts
 * and the unit tests all rely on stable, ordered timestamps. Every record is
 * derived from `DEMO_EPOCH` instead.
 */

/** The moment the demo dataset was "captured" (UTC). */
export const DEMO_EPOCH = Date.parse('2025-03-18T09:30:00.000Z');

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** ISO timestamp `minutes` before the demo epoch. */
export function agoMinutes(minutes: number): string {
  return new Date(DEMO_EPOCH - minutes * MINUTE).toISOString();
}

/** ISO timestamp `hours` before the demo epoch. */
export function agoHours(hours: number): string {
  return new Date(DEMO_EPOCH - hours * HOUR).toISOString();
}

/** ISO timestamp `days` before the demo epoch. */
export function agoDays(days: number): string {
  return new Date(DEMO_EPOCH - days * DAY).toISOString();
}

/** ISO timestamp `minutes` after the demo epoch (positive = future). */
export function aheadMinutes(minutes: number): string {
  return new Date(DEMO_EPOCH + minutes * MINUTE).toISOString();
}

/** ISO timestamp `seconds` before the demo epoch. */
export function agoSeconds(seconds: number): string {
  return new Date(DEMO_EPOCH - seconds * 1000).toISOString();
}

/** ISO timestamp `hours` after the demo epoch. */
export function aheadHours(hours: number): string {
  return new Date(DEMO_EPOCH + hours * HOUR).toISOString();
}

/** ISO timestamp `days` after the demo epoch. */
export function aheadDays(days: number): string {
  return new Date(DEMO_EPOCH + days * DAY).toISOString();
}

/** The demo epoch itself. */
export const DEMO_NOW_ISO = new Date(DEMO_EPOCH).toISOString();

/** Stable pseudo-random generator so every reload renders the same numbers. */
export function seeded(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x1_0000_0000;
  };
}

/** Pick an element deterministically from `items` using `seed`. */
export function pick<T>(items: readonly T[], seed: number): T {
  const index = Math.abs(Math.trunc(seed)) % items.length;
  return items[index] as T;
}

/**
 * Build a daily series ending at the demo epoch.
 * `shape` biases the value between 0 and 1 (0 = low end, 1 = high end).
 */
export function dailySeries(
  days: number,
  base: number,
  amplitude: number,
  seed: number,
  trend = 0,
): { ts: string; value: number }[] {
  const rand = seeded(seed);
  const points: { ts: string; value: number }[] = [];
  for (let i = days - 1; i >= 0; i -= 1) {
    const progress = (days - 1 - i) / Math.max(1, days - 1);
    const noise = rand() - 0.5;
    const value = base + amplitude * noise + trend * progress;
    points.push({
      ts: agoDays(i),
      value: Math.max(0, Math.round(value * 100) / 100),
    });
  }
  return points;
}
