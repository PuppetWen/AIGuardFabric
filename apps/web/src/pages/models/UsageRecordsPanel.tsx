import { useTranslation } from 'react-i18next';

import { Table, Tag, Tooltip } from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import type { TokenUsageRecord } from '@/types/domain';
import { formatDateTime, formatCny } from '@/utils/format';

interface UsageRecordsPanelProps {
  loading: boolean;
  error: unknown;
  records: TokenUsageRecord[];
  pagination: { current: number; pageSize: number; total: number };
  onPageChange: (page: number, pageSize: number) => void;
}

/** Raw per-call token usage records. */
export function UsageRecordsPanel({ loading, error, records, pagination, onPageChange }: UsageRecordsPanelProps) {
  const { t } = useTranslation();
  const locale = useAppLocale();

  const usageColumns: ColumnsType<TokenUsageRecord> = [
    { title: t('common.status'), key: 'mode', width: 140, render: (_, row) =>
      <><Tag color={row.mocked ? 'gold' : 'blue'}>{row.mocked ? t('models.mockBadge') : t('common.real')}</Tag>
        {row.cacheHit && <Tag>Cache</Tag>}</> },
    {
      title: t('models.usage.column.time'),
      dataIndex: 'ts',
      width: 168,
      render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
    },
    { title: t('models.usage.column.agent'), dataIndex: 'agentName', width: 200 },
    {
      title: t('models.usage.column.model'),
      dataIndex: 'model',
      width: 210,
      render: (value: string) => <span className="agf-mono" style={{ fontSize: 12 }}>{value}</span>,
    },
    {
      title: t('models.usage.column.input'),
      dataIndex: 'inputTokens',
      width: 124,
      align: 'right',
      render: (value: number, row) => {
        const read = row.cacheReadTokens ?? 0;
        const write = row.cacheWriteTokens ?? 0;
        const oneHour = Math.min(row.cacheWrite1hTokens ?? 0, write);
        if (read === 0 && write === 0) return value.toLocaleString();
        return <Tooltip title={<>
          <div>{t('models.usage.cacheRead')}: {read.toLocaleString()}</div>
          <div>{t('models.usage.cacheWrite5m')}: {(write - oneHour).toLocaleString()}</div>
          <div>{t('models.usage.cacheWrite1h')}: {oneHour.toLocaleString()}</div>
        </>}><span style={{ cursor: 'help', textDecoration: 'underline dotted' }}>{value.toLocaleString()}</span></Tooltip>;
      },
    },
    {
      title: t('models.usage.column.output'),
      dataIndex: 'outputTokens',
      width: 124,
      align: 'right',
      render: (value: number) => value.toLocaleString(),
    },
    {
      title: t('models.usage.column.cost'),
      dataIndex: 'costCny',
      width: 116,
      align: 'right',
      render: (value: number) => <span className="agf-mono">{formatCny(value, 6)}</span>,
    },
  ];

  return (
    <Panel title={t('models.usage.detail')}>
      <DataState loading={loading} error={error}>
        <Table<TokenUsageRecord>
          rowKey="id"
          size="small"
          columns={usageColumns}
          dataSource={records}
          scroll={{ x: 1080 }}
          pagination={{
            current: pagination.current,
            pageSize: pagination.pageSize,
            total: pagination.total,
            showSizeChanger: true,
            onChange: onPageChange,
            showTotal: (total) => t('common.total', { count: total }),
          }}
        />
      </DataState>
    </Panel>
  );
}
