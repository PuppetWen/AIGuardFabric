import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

import { Alert, Button, Empty, Skeleton, Space } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';

import { PageHeader } from './PageHeader';

export interface DataStateProps {
  loading?: boolean;
  error?: unknown;
  empty?: boolean;
  /** Rows shown by the loading skeleton. */
  skeletonRows?: number;
  children: ReactNode;
  onRetry?: () => void;
}

/**
 * Uniform loading / error / empty handling for a page body.
 *
 * Real-data requests show their failure here; callers may provide retry controls.
 */
export function DataState({
  loading,
  error,
  empty,
  skeletonRows = 4,
  children,
  onRetry,
}: DataStateProps) {
  const { t } = useTranslation();

  if (loading) {
    return (
      <div className="agf-panel agf-panel--pad" aria-busy="true" aria-live="polite">
        <Skeleton active paragraph={{ rows: skeletonRows }} />
      </div>
    );
  }

  if (error) {
    return (
      <Alert
        type="error"
        showIcon
        message={t('error.server')}
        description={error instanceof Error ? error.message : String(error)}
        action={
          onRetry ? (
            <Button size="small" icon={<ReloadOutlined />} onClick={onRetry}>
              {t('error.retry')}
            </Button>
          ) : null
        }
      />
    );
  }

  if (empty) {
    return (
      <div className="agf-panel agf-panel--pad">
        <Empty description={t('common.empty')} />
      </div>
    );
  }

  return <>{children}</>;
}

/** Compact page scaffold for polling / event-stream style pages. */
export function PollingBadge({ intervalMs, paused }: { intervalMs: number; paused?: boolean }) {
  const { t } = useTranslation();
  return (
    <Space size={6}>
      <span
        className="agf-severity-dot"
        style={{ background: paused ? 'var(--agf-text-tertiary)' : 'var(--agf-success)' }}
      />
      <span className="agf-muted">
        {paused ? t('runtime.stream.paused') : `${t('runtime.stream.live')} · ${intervalMs / 1000}s`}
      </span>
    </Space>
  );
}

export { PageHeader };
