import { useTranslation } from 'react-i18next';

export function usePolicyText() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  return (cn: string, en: string) => zh ? cn : en;
}
