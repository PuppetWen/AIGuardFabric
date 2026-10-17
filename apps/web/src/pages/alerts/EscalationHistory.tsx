import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Space, Table, Tag, Tooltip } from 'antd';
import { useApiQuery } from '@/api/client';
import { escalationApi, type EscalationReceipt } from '@/api/escalation';
import { DataState } from '@/components/DataState';

export function EscalationHistory() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const [page, setPage] = useState(1);
  const history = useApiQuery('alert-escalation-history', () => escalationApi.history(page), { key: [page], refetchInterval: 30_000 });
  const states: Record<string, string> = zh ? { pending: '待投递', sending: '投递中', retrying: '重试中', delivered: '已送达', failed: '失败', suppressed: '已取消', expired: '详情已过保留期' } : {};
  return <DataState loading={history.isLoading} error={history.error} onRetry={() => void history.refetch()}>
    <Table<EscalationReceipt> size="small" rowKey={r => `${r.alertId}:${r.tier}`} dataSource={history.data?.data.items ?? []}
      scroll={{ x: 860 }} pagination={{ current: page, pageSize: 10, total: history.data?.data.total ?? 0, onChange: setPage, showSizeChanger: false }}
      columns={[
        { title: zh ? '告警' : 'Alert', key: 'alert', width: 220, render: (_, r) => <Link to={`/alerts?alert=${encodeURIComponent(r.alertId)}`}>{r.title ?? r.alertId}</Link> },
        { title: zh ? '升级 / 版本' : 'Tier / version', key: 'tier', render: (_, r) => `L${r.tier} / v${r.policyVersion}` },
        { title: zh ? '入队时间' : 'Queued at', dataIndex: 'enqueuedAt', render: (value: string) => new Date(value).toLocaleString(zh ? 'zh-CN' : 'en-US') },
        { title: zh ? '通知状态' : 'Delivery status', key: 'notifications', render: (_, r) => <Space direction="vertical" size={2}>{r.notifications.map(n => <Tooltip title={n.error} key={n.id}>
          <Tag color={n.status === 'delivered' ? 'green' : n.status === 'failed' ? 'red' : undefined}>{n.kind} · {states[n.status ?? 'pending'] ?? n.status}{n.mocked ? (zh ? '（模拟）' : ' (mock)') : ''}</Tag>
        </Tooltip>)}</Space> },
      ]} />
  </DataState>;
}
