import { useTranslation } from 'react-i18next';

import { Alert, Table, Tag } from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import type { CrossTeamCall } from '@/types/domain';

interface CrossCallsPanelProps {
  loading: boolean;
  error: unknown;
  calls: CrossTeamCall[];
}

/** Cross-team call log, with a warning banner when any call is unauthorized. */
export function CrossCallsPanel({ loading, error, calls }: CrossCallsPanelProps) {
  const { t, i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');

  const unauthorized = calls.filter((call) => call.authorized === false);

  const crossColumns: ColumnsType<CrossTeamCall> = [
    { title: t('alicloud.cross.column.caller'), dataIndex: 'callerTeam', width: 180 },
    { title: t('alicloud.cross.column.callee'), dataIndex: 'calleeTeam', width: 180 },
    {
      title: t('alicloud.cross.column.agent'),
      dataIndex: 'calleeAgent',
      width: 280,
      render: (value: string) => <span className="agf-mono" style={{ fontSize: 12 }}>{value}</span>,
    },
    {
      title: t('alicloud.cross.column.count'),
      dataIndex: 'count24h',
      width: 130,
      align: 'right',
      sorter: (a, b) => a.count24h - b.count24h,
      render: (value: number) => value.toLocaleString(),
    },
    {
      title: t('alicloud.cross.column.authorized'),
      dataIndex: 'authorized',
      width: 130,
      render: (value: boolean | null) =>
        value === true ? (
          <Tag color="green" style={{ marginInlineEnd: 0 }}>
            {t('common.yes')}
          </Tag>
        ) : value === false ? (
          <Tag color="red" style={{ marginInlineEnd: 0 }}>
            {t('common.no')}
          </Tag>
        ) : <Tag>{zh ? '未知' : 'Unknown'}</Tag>,
    },
    {
      title: t('alicloud.cross.column.sensitive'),
      dataIndex: 'sensitiveData',
      width: 148,
      render: (value: boolean | null) => value === true ? <Tag color="orange">{t('common.yes')}</Tag>
        : value === false ? <Tag>{t('common.no')}</Tag> : <Tag>{zh ? '未知' : 'Unknown'}</Tag>,
    },
  ];

  return (
    <Panel title={t('alicloud.cross.title')}>
      {calls.some(call => call.mocked) && <Alert type="info" showIcon style={{ marginBottom: 12 }}
        message={zh ? 'Mock：以下调用链为模拟样本，不是云账号的实际记录。' : 'Mock: these call chains are example fixtures, not observed cloud account traffic.'} />}
      {!loading && calls.length === 0 && <Alert type="info" showIcon style={{ marginBottom: 12 }}
        message={zh ? '尚未采集到跨团队调用记录；团队盘点不会推测调用链。' : 'No cross-team calls have been collected. Inventory reads do not infer call chains.'} />}
      {unauthorized.length > 0 ? (
        <Alert
          style={{ marginBottom: 12 }}
          type="warning"
          showIcon
          message={t('alicloud.cross.unauthorizedWarning', { count: unauthorized.length })}
        />
      ) : null}
      <DataState loading={loading} error={error}>
        <Table<CrossTeamCall>
          rowKey="id"
          size="small"
          columns={crossColumns}
          dataSource={calls}
          pagination={false}
          scroll={{ x: 1240 }}
        />
      </DataState>
    </Panel>
  );
}
