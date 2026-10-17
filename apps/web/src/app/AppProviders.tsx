import type { ReactNode } from 'react';
import { useEffect, useMemo } from 'react';

import { App as AntApp, ConfigProvider, theme } from 'antd';
import enUS from 'antd/locale/en_US';
import zhCN from 'antd/locale/zh_CN';
import { useTranslation } from 'react-i18next';

import { useUiStore } from '@/stores/uiStore';
import '@/locales/i18n';

/**
 * Theme + locale + antd `ConfigProvider`.
 *
 * Dark is the default (`theme.darkAlgorithm`); the light theme swaps in
 * `theme.defaultAlgorithm`. The `--agf-*` CSS variables in `styles/global.css`
 * mirror the same palette so hand-written CSS and antd components agree.
 */
export function AppProviders({ children }: { children: ReactNode }): ReactNode {
  const { i18n } = useTranslation();
  const mode = useUiStore((state) => state.theme);
  const locale = useUiStore((state) => state.locale);

  useEffect(() => {
    void i18n.changeLanguage(locale);
  }, [i18n, locale]);

  const config = useMemo(() => {
    const isDark = mode === 'dark';
    return {
      algorithm: isDark ? theme.darkAlgorithm : theme.defaultAlgorithm,
      token: {
        colorPrimary: isDark ? '#5fa8ff' : '#1a5fd0',
        colorBgBase: isDark ? '#0b0f16' : '#f4f6fb',
        colorBgContainer: isDark ? '#131b29' : '#ffffff',
        colorBgElevated: isDark ? '#182233' : '#ffffff',
        colorBorder: isDark ? '#26324a' : '#d5dced',
        colorText: isDark ? '#e8edf6' : '#101725',
        colorTextSecondary: isDark ? '#a7b3c7' : '#46536b',
        colorSuccess: isDark ? '#3dd68c' : '#0f7a45',
        colorWarning: isDark ? '#f0cc6a' : '#8a6100',
        colorError: isDark ? '#ff8b90' : '#b3252a',
        borderRadius: 8,
        fontFamily:
          "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif",
        fontSize: 14,
      },
      components: {
        Layout: {
          bodyBg: isDark ? '#0b0f16' : '#f4f6fb',
          headerBg: isDark ? '#111826' : '#ffffff',
          siderBg: isDark ? '#111826' : '#ffffff',
        },
        Menu: {
          itemBg: 'transparent',
          subMenuItemBg: 'transparent',
        },
        Table: {
          headerBg: isDark ? '#182233' : '#f2f5fb',
          rowHoverBg: isDark ? '#182233' : '#f5f8fd',
        },
      },
    };
  }, [mode]);

  return (
    <ConfigProvider
      theme={config}
      locale={locale === 'en-US' ? enUS : zhCN}
      componentSize="middle"
      form={{ validateMessages: { required: '${label}' } }}
    >
      <AntApp>{children}</AntApp>
    </ConfigProvider>
  );
}

export default AppProviders;
