import { ObservationGuide } from '../ObservationGuide';
import { useTranslation } from 'react-i18next';

import { Space, Table, Tag, Tooltip, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { DataState } from '@/components/DataState';
import { HealthTag } from '@/components/Tags';
import type { ModelEndpoint } from '@/types/domain';
import { HEALTH_HEX } from '@/utils/palette';

interface ModelEndpointsTableProps {
  loading: boolean;
  error: unknown;
  endpoints: ModelEndpoint[];
  pagination: { current: number; pageSize: number; total: number };
  onPageChange: (page: number, pageSize: number) => void;
}

/** Model endpoint inventory across vendors and regions. */
export function ModelEndpointsTable({ loading, error, endpoints, pagination, onPageChange }: ModelEndpointsTableProps) {
  const { t } = useTranslation();

  const endpointColumns: ColumnsType<ModelEndpoint> = [
    {
      title: t('models.column.vendor'),
      dataIndex: 'vendor',
      width: 132,
      render: (vendor: string) => <Tag color="geekblue">{vendor}</Tag>,
    },
    {
      title: t('models.column.model'),
      dataIndex: 'model',
      width: 220,
      render: (model: string, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Text strong style={{ fontSize: 13 }}>
            {model}
          </Typography.Text>
          <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
            {record.id}
          </span>
        </Space>
      ),
    },
    {
      title: t('models.column.endpoint'),
      dataIndex: 'endpoint',
      width: 280,
      render: (value: string) => (
        <Tooltip title={value}>
          <span
            className="agf-mono"
            style={{
              fontSize: 12,
              display: 'inline-block',
              maxWidth: 270,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              verticalAlign: 'middle',
            }}
          >
            {value}
          </span>
        </Tooltip>
      ),
    },
    {
      title: t('models.column.local'),
      dataIndex: 'local',
      width: 118,
      render: (local: boolean | null) => local === null ? t('common.unknown') :
        local ? (
          <Tag color="green" style={{ marginInlineEnd: 0 }}>
            {t('models.local.yes')}
          </Tag>
        ) : (
          <Tag color="blue" style={{ marginInlineEnd: 0 }}>
            {t('models.local.no')}
          </Tag>
        ),
    },
    {
      title: t('models.column.price'),
      key: 'price',
      width: 176,
      render: (_value, record) => (
        <span className="agf-mono" style={{ fontSize: 12 }}>
          {record.inputPricePerKTok === null && record.outputPricePerKTok === null ? t('common.unknown') : t('models.priceFormat', {
            input: record.inputPricePerKTok?.toFixed(6) ?? t('common.unknown'),
            output: record.outputPricePerKTok?.toFixed(6) ?? t('common.unknown'),
          })}
        </span>
      ),
    },
    {
      title: t('models.column.priority'),
      dataIndex: 'priority',
      width: 106,
      align: 'right',
      render: (value: number | null) => value ?? t('common.unknown'),
    },
    {
      title: t('models.column.fallback'),
      dataIndex: 'fallback',
      width: 138,
      render: (fallback: boolean | null) => fallback === null ? t('common.unknown') :
        fallback ? (
          <Tag color="orange" style={{ marginInlineEnd: 0 }}>
            {t('models.fallback.yes')}
          </Tag>
        ) : (
          <Tag color="green" style={{ marginInlineEnd: 0 }}>
            {t('models.fallback.no')}
          </Tag>
        ),
    },
    {
      title: t('models.column.health'),
      dataIndex: 'health',
      width: 120,
      render: (_value, record) => <HealthTag health={record.health} />,
    },
    {
      title: t('models.column.latency'),
      dataIndex: 'latencyP95Ms',
      width: 122,
      align: 'right',
      render: (value: number | null) => value === null ? t('common.unknown') : (
        <span style={{ color: value > 1_500 ? HEALTH_HEX.degraded : undefined }} className="agf-mono">
          {value} {t('unit.msShort')}
        </span>
      ),
    },
    {
      title: t('common.status'),
      key: 'mock',
      width: 108,
      render: (_value, record) =>
        record.mockMode === null ? t('common.unknown') : record.mockMode ? <Tag color="gold">{t('models.mockBadge')}</Tag> : <Tag>{t('common.real')}</Tag>,
    },
  ];

  return (
    <><ObservationGuide /><DataState loading={loading} error={error} skeletonRows={6}>
      <Table<ModelEndpoint>
        rowKey="id"
        size="middle"
        columns={endpointColumns}
        dataSource={endpoints}
        scroll={{ x: 1760 }}
        pagination={{ ...pagination, onChange: onPageChange, showSizeChanger: true,
          showTotal: total => t('common.total', { count: total }) }}
      />
    </DataState></>
  );
}
