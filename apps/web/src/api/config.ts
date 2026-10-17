/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

/** Base URL for the gateway. Empty string keeps requests same-origin (`/api/…`). */
export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? '';

/** Per-request timeout before falling back to demo data. */
export const API_TIMEOUT_MS: number = Number(import.meta.env.VITE_API_TIMEOUT_MS ?? 2_500);

/** `VITE_FORCE_DEMO=true` pins the console to the demo dataset. */
export const FORCE_DEMO: boolean =
  String(import.meta.env.VITE_FORCE_DEMO ?? '').toLowerCase() === 'true';
