import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Descriptions, Drawer, Space, Typography } from 'antd';
import { DataState } from '@/components/DataState';
import { SeverityTag } from '@/components/Tags';
import { useDetailLink } from '@/components/useDetailLink';
import type { Alert } from '@/types/domain';
import { formatDateTime } from '@/utils/format';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { SecurityAnalysisPanel } from '@/components/SecurityAnalysisPanel';

export function AlertDetail() {
  const { t, i18n } = useTranslation();
  const locale = useAppLocale();
  const { id, detail, select, value } = useDetailLink<{ alert: Alert & { assetIds?: string[]; findingIds?: string[]; caseId?: string } }>('alert', '/api/v1/alerts');
  const alert = value?.alert;
  return <Drawer open={Boolean(id)} onClose={() => select(null)} width={760}
    title={`${i18n.language.startsWith('zh') ? '告警详情' : 'Alert detail'} · ${id}`}>
    <DataState loading={detail.isLoading} error={detail.error} onRetry={() => void detail.refetch()}>
      {alert && <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <Typography.Title level={4}>{alert.title}</Typography.Title>
        <Space><SeverityTag severity={alert.severity} /><span>{t(`status.${alert.status}`)}</span></Space>
        <Typography.Paragraph style={{ whiteSpace: 'pre-wrap' }}>{alert.description}</Typography.Paragraph>
        <Descriptions bordered column={1} size="small" items={[
          { key: 'owner', label: t('alerts.column.assignee'), children: alert.assignee ?? '—' },
          { key: 'first', label: i18n.language.startsWith('zh') ? '首次发现' : 'First seen', children: formatDateTime(alert.firstSeenAt, locale) },
          { key: 'last', label: t('alerts.column.lastSeen'), children: formatDateTime(alert.lastSeenAt, locale) },
          { key: 'count', label: i18n.language.startsWith('zh') ? '聚合次数' : 'Occurrences', children: alert.aggregateCount },
          { key: 'assets', label: t('alerts.column.asset'), children: <Space direction="vertical">{(alert.assetIds ?? []).map(asset => <Link key={asset} to={`/assets/${encodeURIComponent(asset)}`}>{asset}</Link>)}</Space> },
          { key: 'findings', label: t('findings.title'), children: <Space direction="vertical">{(alert.findingIds ?? []).map(finding => <Link key={finding} to={`/findings?finding=${encodeURIComponent(finding)}`}>{finding}</Link>)}</Space> },
          { key: 'case', label: i18n.language.startsWith('zh') ? '关联案件' : 'Related case', children: alert.caseId ? <Link to={`/cases/${encodeURIComponent(alert.caseId)}`}>{alert.caseId}</Link> : '—' },
        ]} />
        <SecurityAnalysisPanel key={alert.id} resource="alerts" id={alert.id} />
      </Space>}
    </DataState>
  </Drawer>;
}
