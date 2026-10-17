import { useTranslation } from 'react-i18next';
import { guideChinese, guideEnglish } from './guideCopy';

export function useGuideCopy() {
  const { i18n } = useTranslation();
  return (i18n.resolvedLanguage ?? i18n.language).startsWith('zh') ? guideChinese : guideEnglish;
}
