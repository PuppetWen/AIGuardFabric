import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

import enUS from '@/locales/en-US';
import zhCN from '@/locales/zh-CN';
export const SUPPORTED_LOCALES = ['zh-CN', 'en-US'] as const;
export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];

export const LOCALE_LABEL: Record<SupportedLocale, string> = {
  'zh-CN': '简体中文',
  'en-US': 'English',
};

export const DEFAULT_LOCALE: SupportedLocale = 'zh-CN';

export const LOCALE_STORAGE_KEY = 'aigf.locale';

export function isSupportedLocale(value: unknown): value is SupportedLocale {
  return typeof value === 'string' && (SUPPORTED_LOCALES as readonly string[]).includes(value);
}

/** Read the persisted locale, falling back to the browser language, then zh-CN. */
export function detectLocale(): SupportedLocale {
  try {
    const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    if (isSupportedLocale(stored)) {
      return stored;
    }
  } catch {
    /* storage unavailable (private mode / SSR) — fall through */
  }
  const nav = typeof navigator === 'undefined' ? '' : navigator.language;
  if (nav.toLowerCase().startsWith('en')) {
    return 'en-US';
  }
  return DEFAULT_LOCALE;
}

export function persistLocale(locale: SupportedLocale): void {
  try {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, locale);
  } catch {
    /* ignore */
  }
}

void i18n.use(initReactI18next).init({
  resources: {
    'zh-CN': { translation: zhCN },
    'en-US': { translation: enUS },
  },
  lng: detectLocale(),
  fallbackLng: DEFAULT_LOCALE,
  supportedLngs: [...SUPPORTED_LOCALES],
  // Keys are flat with dots; i18next's default `keySeparator: '.'` resolves them
  // through nested objects, which the flat resources above provide implicitly.
  keySeparator: '.',
  nsSeparator: false,
  interpolation: { escapeValue: false },
  returnNull: false,
  react: { useSuspense: false },
});

export default i18n;
