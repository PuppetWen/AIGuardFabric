/** Ant Design reverses this comparator for descending order; unknowns stay last. */
export function compareRiskScores(
  a: { riskScore: number | null }, b: { riskScore: number | null }, order?: 'ascend' | 'descend' | null,
): number {
  return compareMeasurements(a.riskScore, b.riskScore, order);
}

/** Missing or invalid measurements sort last in either Ant Design direction. */
export function compareMeasurements(
  a: number | null | undefined, b: number | null | undefined,
  order?: 'ascend' | 'descend' | null,
): number {
  const left = a === null || a === undefined || !Number.isFinite(a) ? null : a;
  const right = b === null || b === undefined || !Number.isFinite(b) ? null : b;
  if (left === right) return 0;
  if (left === null) return order === 'ascend' ? 1 : -1;
  if (right === null) return order === 'ascend' ? -1 : 1;
  return left - right;
}

export function observationStatus(
  online: boolean | null, seen: string | null, interval: number | null, now: number,
): boolean | null {
  if (online === false) return false;
  if (online === null || !seen) return null;
  const age = now - Date.parse(seen);
  if (!Number.isFinite(age) || age < 0) return null;
  const window = interval !== null && interval > 0 ? interval * 3_000 : 300_000;
  return age <= window;
}
