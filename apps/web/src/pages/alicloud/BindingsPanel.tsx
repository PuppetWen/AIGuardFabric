import { useTranslation } from 'react-i18next';

import { Space, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import { HealthTag } from '@/components/Tags';
import type { ServiceBinding } from '@/types/domain';
import { aliCloudServiceKey } from '@/utils/labels';

interface BindingsPanelProps {
  loading: boolean;
  error: unknown;
  bindings: ServiceBinding[];
}

/** Aliyun service bindings attached to the console. */
export function BindingsPanel({ loading, error, bindings }: BindingsPanelProps) {
  const { t } = useTranslation();

  const bindingColumns: ColumnsType<ServiceBinding> = [
    {
      title: t('alicloud.bindings.service'),
      dataIndex: 'service',
      width: 250,
      render: (_value, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Text strong style={{ fontSize: 13 }}>
            {t(aliCloudServiceKey(record.service))}
          </Typography.Text>
          <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
            {record.displayName}
          </span>
        </Space>
      ),
    },
    {
      title: t('alicloud.bindings.bound'),
      dataIndex: 'bound',
      width: 122,
      render: (value: boolean) =>
        value ? (
          <Tag color="green" style={{ marginInlineEnd: 0 }}>
            {t('alicloud.bindings.boundYes')}
          </Tag>
        ) : (
          <Tag color="red" style={{ marginInlineEnd: 0 }}>
            {t('alicloud.bindings.boundNo')}
          </Tag>
        ),
    },
    {
      title: t('alicloud.bindings.resource'),
      dataIndex: 'resourceId',
      width: 320,
      render: (value: string | null) =>
        value ? <span className="agf-mono" style={{ fontSize: 12 }}>{value}</span> : <span className="agf-tertiary">—</span>,
    },
    { title: t('alicloud.bindings.region'), dataIndex: 'region', width: 122 },
    {
      title: t('common.health'),
      dataIndex: 'health',
      width: 122,
      render: (_value, record) => <HealthTag health={record.health} />,
    },
    { title: t('alicloud.bindings.note'), dataIndex: 'note', width: 380 },
  ];

  return (
    <Panel title={t('alicloud.bindings.title')}>
      <DataState loading={loading} error={error}>
        <Table<ServiceBinding>
          rowKey="service"
          size="small"
          columns={bindingColumns}
          dataSource={bindings}
          pagination={false}
          scroll={{ x: 1480 }}
        />
      </DataState>
    </Panel>
  );
}
