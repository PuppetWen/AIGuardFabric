import type { ReactNode } from 'react';
import { createContext, useContext, useMemo } from 'react';

import type { AppLocale } from '@/utils/format';

import { useUiStore } from '@/stores/uiStore';

const LocaleContext = createContext<AppLocale>('zh-CN');

/** Locale value for non-i18n formatters (dayjs, number/date formatting). */
export function useAppLocale(): AppLocale {
  return useContext(LocaleContext);
}

export function AppLocaleProvider({ children }: { children: ReactNode }): ReactNode {
  const locale = useUiStore((state) => state.locale);
  const value = useMemo<AppLocale>(() => (locale === 'en-US' ? 'en-US' : 'zh-CN'), [locale]);
  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>;
}
