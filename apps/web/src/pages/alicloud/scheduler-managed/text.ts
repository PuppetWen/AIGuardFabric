import { useTranslation } from 'react-i18next';
export function useText() { const { i18n } = useTranslation(); return (cn: string, en: string) => i18n.language.startsWith('zh') ? cn : en; }
export const uuid = (value: string) => /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export const digest = (value: string) => /^[0-9a-f]{64}$/.test(value);
export function safeFailure(cause: unknown) {
  // Opaque provider/transport details are intentionally never echoed by this workflow.
  const status = cause && typeof cause === 'object' && 'status' in cause ? Number(cause.status) : 0;
  return Number.isSafeInteger(status) && status >= 400 && status <= 599 ? `HTTP ${status}` : 'Local request result unavailable / 本地请求结果不可用';
}
export function previewRejected(cause: unknown) {
  const status = cause && typeof cause === 'object' && 'status' in cause ? Number(cause.status) : 0;
  return Number.isInteger(status) && status >= 400 && status < 500 && status !== 408 && status !== 429;
}
export const kinds = ['asset-inventory', 'log-pull', 'redteam-cruise', 'rule-hot-reload', 'report', 'archive'] as const;

export function positiveInt64(value: unknown): value is string {
  return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value) <= 9223372036854775807n;
}
