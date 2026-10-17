import { useSyncExternalStore } from 'react';
import { useTranslation } from 'react-i18next';

import { Alert, type AlertProps } from 'antd';
import { ApiOutlined, ExperimentOutlined } from '@ant-design/icons';

import { getDataSourceSnapshot, subscribeDataSource, type DataSourceSnapshot } from '@/api/client';
import { formatDateTime } from '@/utils/format';
import { useAppLocale } from '@/app/AppLocaleProvider';

/**
 * Subscribes to the API client's data-source flag.
 *
 * `useSyncExternalStore` is used rather than a zustand store so the client stays
 * framework-agnostic and unit-testable without React.
 */
export function useDataSource(): DataSourceSnapshot {
  return useSyncExternalStore(subscribeDataSource, getDataSourceSnapshot, getDataSourceSnapshot);
}

/**
 * The "演示数据（后端未连接）" banner.
 *
 * Renders nothing while live data is flowing, so a connected deployment is
 * unaffected. When the forced flag is set it says so explicitly instead.
 */
export function DemoModeBanner({ closable = false }: { closable?: boolean }) {
  const { t } = useTranslation();
  const locale = useAppLocale();
  const { source, reason, lastSyncAt } = useDataSource();

  if (source !== 'demo') {
    return null;
  }

  const forced = reason === 'forced' || reason === 'VITE_FORCE_DEMO=true';
  const type: AlertProps['type'] = forced ? 'info' : 'warning';
  const message = forced ? t('layout.demoForced') : t('layout.demoMode');
  const description = forced
    ? t('layout.demoModeTip')
    : `${t('layout.demoModeTip')}${lastSyncAt ? ` · ${t('layout.lastSync', { time: formatDateTime(new Date(lastSyncAt).toISOString(), locale) })}` : ''}`;

  return (
    <Alert
      className="agf-demo-banner"
      type={type}
      showIcon
      icon={forced ? <ExperimentOutlined /> : <ApiOutlined />}
      banner
      closable={closable}
      message={message}
      description={description}
      data-testid="demo-mode-banner"
    />
  );
}

export default DemoModeBanner;
