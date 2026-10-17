import { useCallback } from 'react';
import { useTranslation } from 'react-i18next';
export type Text = (cn: string, en: string) => string;
export function usePublicationText(): Text {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  return useCallback((cn, en) => zh ? cn : en, [zh]);
}
export const uuid = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export const revisionLabel = (items: { policyId: string; version: number }[] | null) =>
  items === null ? '—' : items.map(item => `${item.policyId} @ v${item.version}`).join(', ');
export function failure(cause: unknown, text: Text) {
  return cause instanceof Error ? cause.message : text('操作失败；已保存回执和草稿保留。', 'The operation failed; saved receipts and the draft remain.');
}
