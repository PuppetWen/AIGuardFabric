import { create } from 'zustand';

import type { SupportedLocale } from '@/locales/i18n';
import { detectLocale, persistLocale } from '@/locales/i18n';

export type ThemeMode = 'dark' | 'light';

export const THEME_STORAGE_KEY = 'aigf.theme';
export const SIDEBAR_STORAGE_KEY = 'aigf.sidebarCollapsed';

function readTheme(): ThemeMode {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') {
      return stored;
    }
  } catch {
    /* ignore */
  }
  // Dark is the documented default.
  return 'dark';
}

function readCollapsed(): boolean {
  try {
    return window.localStorage.getItem(SIDEBAR_STORAGE_KEY) === 'true';
  } catch {
    return false;
  }
}

function applyThemeAttribute(theme: ThemeMode): void {
  if (typeof document === 'undefined') {
    return;
  }
  document.documentElement.setAttribute('data-theme', theme);
}

export interface UiSlice {
  theme: ThemeMode;
  locale: SupportedLocale;
  sidebarCollapsed: boolean;
  setTheme: (theme: ThemeMode) => void;
  toggleTheme: () => void;
  setLocale: (locale: SupportedLocale) => void;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
}

export const useUiStore = create<UiSlice>((set, get) => {
  const theme = readTheme();
  applyThemeAttribute(theme);
  return {
    theme,
    locale: detectLocale(),
    sidebarCollapsed: readCollapsed(),
    setTheme: (next) => {
      applyThemeAttribute(next);
      try {
        window.localStorage.setItem(THEME_STORAGE_KEY, next);
      } catch {
        /* ignore */
      }
      set({ theme: next });
    },
    toggleTheme: () => {
      get().setTheme(get().theme === 'dark' ? 'light' : 'dark');
    },
    setLocale: (locale) => {
      persistLocale(locale);
      set({ locale });
    },
    toggleSidebar: () => {
      get().setSidebarCollapsed(!get().sidebarCollapsed);
    },
    setSidebarCollapsed: (collapsed) => {
      try {
        window.localStorage.setItem(SIDEBAR_STORAGE_KEY, String(collapsed));
      } catch {
        /* ignore */
      }
      set({ sidebarCollapsed: collapsed });
    },
  };
});
