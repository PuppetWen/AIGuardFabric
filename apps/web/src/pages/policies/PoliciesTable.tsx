import { useTranslation } from 'react-i18next';

import { Button, Space, Table, Tag, Tooltip, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { CheckCircleOutlined, CloseCircleOutlined } from '@ant-design/icons';

import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState } from '@/components/DataState';
import { ActionTag, Chip } from '@/components/Tags';
import type { InterceptPoint, Policy, PolicyLifecycle } from '@/types/domain';
import { POLICY_LIFECYCLE_HEX } from '@/utils/palette';
import { formatDateTime, formatNumber } from '@/utils/format';
import { interceptPointKey, policyActionKey } from '@/utils/labels';

import { ACTIONS } from './policies.data';

interface PoliciesTableProps {
  loading: boolean;
  error: unknown;
  policies: Policy[];
  onEdit: (policy: Policy) => void;
  onHistory: (policy: Policy) => void;
}

/** Policy roster; opening a row loads it into the editor drawer. */
export function PoliciesTable({ loading, error, policies, onEdit, onHistory }: PoliciesTableProps) {
  const { t } = useTranslation();
  const locale = useAppLocale();

  const columns: ColumnsType<Policy> = [
    {
      title: t('policies.column.name'),
      dataIndex: 'name',
      width: 300,
      render: (name: string, record) => (
        <Space direction="vertical" size={2}>
          <Space size={6}>
            <Typography.Link onClick={() => onEdit(record)}>{name}</Typography.Link>
            {record.dryRun ? <Tag color="gold">{t('policies.editor.dryRun')}</Tag> : null}
          </Space>
          <span className="agf-tertiary" style={{ fontSize: 12 }}>
            {record.description}
          </span>
          <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
            {record.id}
          </span>
        </Space>
      ),
    },
    {
      title: t('policies.column.action'),
      dataIndex: 'action',
      width: 112,
      filters: ACTIONS.map((value) => ({ text: t(policyActionKey(value)), value })),
      onFilter: (value, record) => record.action === value,
      render: (_value, record) => <ActionTag action={record.action} />,
    },
    {
      title: t('policies.column.priority'),
      dataIndex: 'priority',
      width: 106,
      align: 'right',
      sorter: (a, b) => a.priority - b.priority,
      render: (value: number) => <span className="agf-mono">{value}</span>,
    },
    {
      title: t('policies.column.interceptPoints'),
      dataIndex: 'interceptPoints',
      width: 260,
      render: (points: InterceptPoint[]) => (
        <span className="agf-inline-list">
          {points.map((point) => (
            <Tag key={point} style={{ marginInlineEnd: 0 }}>
              {t(interceptPointKey(point))}
            </Tag>
          ))}
        </span>
      ),
    },
    {
      title: t('policies.column.lifecycle'),
      dataIndex: 'lifecycle',
      width: 116,
      render: (value: PolicyLifecycle) => (
        <Chip color={POLICY_LIFECYCLE_HEX[value]}>{t(`status.${value}`)}</Chip>
      ),
    },
    {
      title: t('policies.column.signature'),
      dataIndex: 'signature',
      width: 186,
      render: (_value, record) => (
        <Space size={6}>
          {record.signature.status === 'signed' ? (
            <CheckCircleOutlined style={{ color: 'var(--agf-success)' }} />
          ) : (
            <CloseCircleOutlined style={{ color: 'var(--agf-danger)' }} />
          )}
          <Tooltip title={`${record.signature.signer} · ${record.signature.keyId}`}>
            <span style={{ fontSize: 12 }}>{t(`policies.signature.${record.signature.status}`)}</span>
          </Tooltip>
        </Space>
      ),
    },
    {
      title: t('policies.column.hits'),
      dataIndex: 'hitCount24h',
      width: 112,
      align: 'right',
      sorter: (a, b) => a.hitCount24h - b.hitCount24h,
      render: (value: number) => formatNumber(value),
    },
    {
      title: t('policies.column.blocked'),
      dataIndex: 'blockedCount24h',
      width: 112,
      align: 'right',
      render: (value: number) => (value > 0 ? <span style={{ color: 'var(--agf-danger)' }}>{value}</span> : '0'),
    },
    {
      title: t('policies.column.updatedAt'),
      dataIndex: 'updatedAt',
      width: 158,
      sorter: (a, b) => Date.parse(a.updatedAt) - Date.parse(b.updatedAt),
      render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
    },
    {
      title: t('common.actions'),
      key: 'actions',
      fixed: 'right',
      width: 180,
      render: (_value, record) => (
        <Space size={0}><Button size="small" type="link" onClick={() => onEdit(record)}>
          {t('common.edit')}
        </Button><Button size="small" type="link" onClick={()=>onHistory(record)}>版本 / Versions</Button></Space>
      ),
    },
  ];

  return (
    <DataState loading={loading} error={error} skeletonRows={6}>
      <Table<Policy>
        rowKey="id"
        size="middle"
        columns={columns}
        dataSource={policies}
        scroll={{ x: 1880 }}
        pagination={{
          pageSize: 10,
          showSizeChanger: true,
          showTotal: (total) => t('common.total', { count: total }),
        }}
      />
    </DataState>
  );
}
