import { useState } from 'react';
import { Alert, Button, Space, Table, Tag } from 'antd';
import { useTranslation } from 'react-i18next';
import { useApiQuery } from '@/api/client';
import { notificationApi, type DeliveryRow } from '@/api/notifications';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { formatDateTime } from '@/utils/format';

export function NotificationHistory() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const locale = useAppLocale();
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const query = useApiQuery('notification-deliveries', notificationApi.history, { refetchInterval: 10000 });
  const statuses: Record<string, string> = {
    pending: text('等待投递', 'Pending'), sending: text('投递中', 'Sending'),
    retrying: text('等待重试', 'Retrying'), delivered: text('已投递', 'Delivered'),
    failed: text('失败', 'Failed'), suppressed: text('已取消 / 抑制', 'Cancelled / suppressed'),
  };
  const retry = async (row: DeliveryRow) => {
    if (!row.id) return;
    setBusy(row.id); setError('');
    try { await notificationApi.retry(row.id); await query.refetch(); }
    catch (failure) { setError(String(failure)); }
    finally { setBusy(''); }
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Alert type="info" showIcon message={text('通知投递与重试', 'Notification delivery and retries')}
      description={text('消息加密入队后投递；后台每 10 秒检查，最多自动尝试 8 次。修好渠道后可手动重试失败消息。重试沿用原编号；外部服务不支持幂等时，网络中断可能造成重复收件。',
        'Messages are encrypted and queued before delivery. The worker checks every 10 seconds and makes up to 8 attempts. Fix the channel, then retry failed messages. Retries keep the same ID; receivers without idempotency support may receive duplicates after a network interruption.')} />
    {(error || query.error) && <Alert type="error" showIcon message={error || String(query.error)} />}
    <Button onClick={() => void query.refetch()} loading={query.isFetching}>{text('刷新投递记录', 'Refresh deliveries')}</Button>
    <Table<DeliveryRow> size="small" rowKey={(row) => row.id ?? row.channelId + row.at}
      loading={query.isLoading} dataSource={query.data?.data ?? []} pagination={{ pageSize: 10 }} scroll={{ x: 950 }}
      columns={[
        { title: text('渠道', 'Channel'), dataIndex: 'kind' },
        { title: text('状态', 'Status'), render: (_, row) => <Tag color={row.status === 'delivered' || row.outcome === 'delivered' ? 'green' : row.status === 'failed' ? 'red' : 'blue'}>
          {statuses[row.status ?? row.outcome] ?? row.outcome}{row.mocked ? text('（模拟）', ' (mock)') : ''}
        </Tag> },
        { title: text('尝试次数', 'Attempts'), dataIndex: 'attempts' },
        { title: text('最近处理', 'Last update'), render: (_, row) => formatDateTime(row.at, locale) },
        { title: text('下次重试', 'Next attempt'), render: (_, row) => row.nextAttemptAt ? formatDateTime(row.nextAttemptAt, locale) : '—' },
        { title: text('原因 / 回执', 'Reason / receipt'), render: (_, row) => row.error
          || (typeof row.receipt === 'string' ? row.receipt : row.receipt?.detail) || '—' },
        { title: text('操作', 'Actions'), render: (_, row) =>
          row.id && ['failed', 'retrying'].includes(row.status ?? '') && <Button size="small" disabled={!!busy}
            loading={busy === row.id} onClick={() => void retry(row)}>{text('重试', 'Retry')}</Button> },
      ]} />
  </Space>;
}

