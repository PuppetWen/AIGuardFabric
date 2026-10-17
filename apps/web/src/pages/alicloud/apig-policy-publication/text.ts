import { useCallback } from 'react';
import { useTranslation } from 'react-i18next';
export function useApigText() {
  const { i18n } = useTranslation(), zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  return useCallback((cn: string, en: string) => zh ? cn : en, [zh]);
}
export const uuid = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
  && value !== '00000000-0000-0000-0000-000000000000';
export const revisions = (items: { policyId: string; version: number }[] | null | undefined) =>
  items ? items.map(item => `${item.policyId} @ v${item.version}`).join(', ') || '—' : '—';
export const failure = (cause: unknown) => cause instanceof Error ? cause.message : '操作失败；草稿和原回执保留 / Operation failed; the draft and original receipt remain';
