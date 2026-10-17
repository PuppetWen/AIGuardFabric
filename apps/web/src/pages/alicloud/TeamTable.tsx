import { useTranslation } from 'react-i18next';

import { Alert, Button, Progress, Space, Table, Tag } from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState } from '@/components/DataState';
import type { AgentTeam } from '@/types/domain';
import { formatDateTime } from '@/utils/format';

interface TeamTableProps {
  loading: boolean;
  error: unknown;
  teamList: AgentTeam[];
  onSelectTeam: (id: string) => void;
  onManageTeam?: (name: string) => void;
}

/** Agent-team roster; the row links drive the members panel below. */
export function TeamTable({ loading, error, teamList, onSelectTeam, onManageTeam }: TeamTableProps) {
  const { t, i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const locale = useAppLocale();

  const teamColumns: ColumnsType<AgentTeam> = [
    {
      title: t('alicloud.column.name'),
      dataIndex: 'name',
      width: 210,
      render: (name: string, record) => (
        <Space direction="vertical" size={2}>
          <Button type="link" style={{ padding: 0 }} onClick={() => onSelectTeam(record.id)}>{name}</Button>
          {record.mocked && <Tag color="gold">Mock</Tag>}
          <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
            {record.id}
          </span>
        </Space>
      ),
    },
    {
      title: t('alicloud.column.workspace'),
      dataIndex: 'workspaceId',
      width: 180,
      render: (value: string) => <span className="agf-mono" style={{ fontSize: 12 }}>{value}</span>,
    },
    { title: t('alicloud.column.region'), dataIndex: 'region', width: 122 },
    {
      title: t('alicloud.column.members'), dataIndex: 'memberCount', width: 110, align: 'right',
      render: (value: number | null, row) => row.relationshipAvailable === true && typeof value === 'number'
        ? value.toLocaleString() : t('alicloud.relations.countUnknown'),
    },
    {
      title: t('alicloud.relations.evidence'), width: 190,
      render: (_, row) => <Tag color={row.relationshipAvailable === true ? 'blue' : 'gold'}>
        {row.relationshipAvailable === true
          ? t(`alicloud.relations.evidence.${row.relationshipEvidence ?? 'unknown'}`)
          : t('alicloud.relations.unknown')}
      </Tag>,
    },
    {
      title: zh ? '已采集跨团队调用 / 24h' : 'Observed cross-team calls / 24h',
      dataIndex: 'crossTeamCalls24h',
      width: 148,
      align: 'right',
      sorter: (a, b) => a.crossTeamCalls24h - b.crossTeamCalls24h,
      render: (value: number, row) => row.metricsAvailable === false ? '—' : value.toLocaleString(),
    },
    {
      title: t('alicloud.column.risk'),
      dataIndex: 'riskScore',
      width: 150,
      sorter: (a, b) => a.riskScore - b.riskScore,
      render: (value: number, row) => row.riskAvailable === false ? '—' : (
        <Progress
          percent={value}
          size="small"
          strokeColor={value >= 80 ? '#ff8b90' : value >= 60 ? '#ffab7a' : '#8fbaff'}
          format={(percent) => `${percent}`}
        />
      ),
    },
    {
      title: t('alicloud.column.createdAt'),
      dataIndex: 'createdAt',
      width: 168,
      render: (value: string | null) => <span className="agf-mono">{formatDateTime(value ?? '', locale)}</span>,
    },
    {
      title: t('common.actions'),
      key: 'actions',
      width: onManageTeam ? 190 : 100,
      render: (_value, record) => (
        <Space><Button size="small" type="link" onClick={() => onSelectTeam(record.id)}>
          {t('common.detail')}
        </Button>{onManageTeam && <Button size="small" type="link" onClick={() => onManageTeam(record.name)}>{t('teamManagement.entry')}</Button>}</Space>
      ),
    },
  ];

  return (
    <DataState loading={loading} error={error} skeletonRows={5}>
      <Alert type="info" showIcon style={{ marginBottom: 12 }} message={t('alicloud.relations.hint')} />
      <Alert type="info" showIcon style={{ marginBottom: 12 }}
        message={zh ? '统计仅包含最近 24 小时已收到的调用事件，覆盖完整性未知。— 表示该团队尚未观测；有数值也不证明覆盖完整。'
          : 'Counts include received call events from the last 24 hours; coverage completeness is unknown. — means this team is unobserved. A value does not establish complete coverage.'} />
      <Table<AgentTeam>
        rowKey="id"
        size="middle"
        columns={teamColumns}
        dataSource={teamList}
        scroll={{ x: 1620 }}
        pagination={{ pageSize: 6, showTotal: (total) => t('common.total', { count: total }) }}
      />
    </DataState>
  );
}
