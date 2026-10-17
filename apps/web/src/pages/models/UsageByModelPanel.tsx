import { useTranslation } from 'react-i18next';

import { Badge, Space, Statistic, Table, Tooltip } from 'antd';

import { Panel } from '@/components/Panel';
import type { ModelUsageAggregate } from '@/types/domain';
import { compactNumber, formatCny } from '@/utils/format';

interface UsageByModelPanelProps {
  usage: ModelUsageAggregate[];
}

/** Per-model token and cost totals for the current window. */
export function UsageByModelPanel({ usage }: UsageByModelPanelProps) {
  const { t } = useTranslation();

  const totalInput = usage.reduce((sum, row) => sum + row.inputTokens, 0);
  const totalOutput = usage.reduce((sum, row) => sum + row.outputTokens, 0);
  const totalCost = usage.reduce((sum, row) => sum + row.costCny, 0);

  return (
    <Panel
      title={t('models.usage.byModel')}
      extra={
        <Space size={20}>
          <Statistic
            title={t('models.usage.input')}
            value={compactNumber(totalInput)}
            valueStyle={{ fontSize: 16 }}
          />
          <Statistic title={t('models.usage.output')} value={compactNumber(totalOutput)} valueStyle={{ fontSize: 16 }} />
          <Statistic
            title={t('models.usage.cost')}
            value={formatCny(totalCost, 6)}
            valueStyle={{ fontSize: 16, color: 'var(--agf-warning)' }}
          />
        </Space>
      }
    >
      <Table<ModelUsageAggregate>
        rowKey={row => `${row.endpointId}:${row.model}:${row.mocked}`}
        size="small"
        pagination={false}
        dataSource={usage}
        scroll={{ x: 900 }}
        columns={[
          { title: t('models.column.vendor'), dataIndex: 'vendor', width: 130 },
          {
            title: t('models.column.model'),
            dataIndex: 'model',
            width: 230,
            render: (value: string) => <span className="agf-mono" style={{ fontSize: 12 }}>{value}</span>,
          },
          {
            title: t('models.usage.column.input'),
            dataIndex: 'inputTokens',
            width: 140,
            align: 'right',
            render: (value: number) => compactNumber(value),
          },
          {
            title: t('models.usage.column.output'),
            dataIndex: 'outputTokens',
            width: 140,
            align: 'right',
            render: (value: number) => compactNumber(value),
          },
          {
            title: t('models.usage.column.cost'),
            dataIndex: 'costCny',
            width: 120,
            align: 'right',
            render: (value: number) => <span className="agf-mono">{formatCny(value, 6)}</span>,
          },
          {
            title: t('models.usage.detail'),
            dataIndex: 'calls',
            width: 130,
            align: 'right',
            render: (value: number, record) => (
              <Tooltip title={record.endpointId}>
                <Badge count={compactNumber(value)} color="#3d8bfd" />
              </Tooltip>
            ),
          },
        ]}
      />
    </Panel>
  );
}
