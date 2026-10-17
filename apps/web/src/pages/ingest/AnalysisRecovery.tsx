import { useState } from 'react';
import { Alert, Button, Drawer, Input, Select, Space, Table, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useApiQuery } from '@/api/client';
import { callApi } from '@/api/transport';
import { EventEvidenceLink } from '@/components/EventEvidenceLink';
import { useAuthStore } from '@/stores/authStore';

interface Failure {
  eventId: string; attempts: number; totalAttempts: number; version: number;
  errorCode: string; lastError: string; state: string; firstFailedAt: string;
  updatedAt: string; resolvedAt?: string; availableAt?: string;
}
interface HistoryItem { id: string; action: string; actorId: string; previousVersion: number; createdAt: string }
const base = '/api/v1/sources/analysis/failures';
const unavailable = () => { throw new Error('Analysis recovery is unavailable'); };

export function AnalysisRecovery() {
  const tenant = useAuthStore(state => state.tenant?.id);
  return <Recovery key={tenant} tenant={tenant ?? ''} />;
}

function Recovery({ tenant }: { tenant: string }) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState('open');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [busy, setBusy] = useState('');
  const [feedback, setFeedback] = useState<{ error: boolean; text: string }>();
  const [history, setHistory] = useState('');
  const [historyPage, setHistoryPage] = useState(1);
  const labels: Record<string, string> = zh
    ? { open: '待恢复', all: '全部', retrying: '自动重试', paused: '已暂停', quarantined: '已隔离', resolved: '已恢复' }
    : { open: 'Unresolved', all: 'All', retrying: 'Retrying', paused: 'Paused', quarantined: 'Quarantined', resolved: 'Recovered' };
  const reasons: Record<string, string> = {
    invalid_event: '事件结构不兼容：查看来源事件并检查解析器。',
    invalid_rule_or_window: '检查已发布规则参数及关联窗口候选数量上限。',
    configuration: '检查当前规则及分析配置。',
    dependency: '检查数据库、分析超时和服务日志。',
    authorization: '检查组织启停状态及授权。',
    encryption: '核对服务端加密密钥配置，保留原密钥。',
    analysis_failed: '用事件 ID 查服务日志，检查规则输出与数据库状态。',
  };
  const query = useApiQuery('analysis-failures', () => callApi<{ items: Failure[]; total: number; canManage: boolean }>(
    base, unavailable, { noFallback: true, query: { page, page_size: 10, state: filter, q: search } }),
  { enabled: open, key: [page, filter, search], refetchInterval: open ? 15_000 : false });
  const log = useApiQuery('analysis-recovery-history', () => callApi<{ items: HistoryItem[]; total: number }>(
    `${base}/${history}/history`, unavailable, { noFallback: true, query: { page: historyPage, page_size: 10 } }),
  { enabled: !!history && open, key: [history, historyPage] });
  const act = async (row: Failure, action: 'retry' | 'pause') => {
    setBusy(row.eventId); setFeedback(undefined);
    try {
      await callApi(`${base}/${row.eventId}/${action}`, unavailable,
        { method: 'POST', body: { expected_version: row.version }, noFallback: true });
      setFeedback({ error: false, text: action === 'retry'
        ? (zh ? '已重新排队；处理结果将自动刷新。' : 'Queued again; processing status will refresh automatically.')
        : (zh ? '已暂停后续重试；正在完成的事务仍可能成功。' : 'Future retries are paused; an in-flight transaction may still complete.') });
      if (history === row.eventId) void log.refetch();
    } catch (error) {
      setFeedback({ error: true, text: error instanceof Error ? error.message : String(error) });
    } finally { setBusy(''); void query.refetch(); }
  };
  return <>
    <Button onClick={() => setOpen(true)}>{zh ? '查看失败事件与恢复' : 'Failed events and recovery'}</Button>
    <Drawer title={zh ? '事件分析故障恢复' : 'Event analysis recovery'} open={open} width="min(1400px, 96vw)"
      onClose={() => { setOpen(false); setHistory(''); setFeedback(undefined); }}>
      <Space direction="vertical" style={{ width: '100%' }}>
        <Alert showIcon type="info" message={zh ? '先排查原因，再重试' : 'Fix the cause before retrying'}
          description={zh ? '同一事件连续失败 8 次后自动隔离，原始事件保留。修正规则、缩小关联窗口或恢复数据库后，点“重新排队”。暂停只阻止后续尝试。恢复使用当前规则并保留处置历史，不重复已完成的发现和告警。'
            : 'Eight consecutive failures quarantine the event without deleting it. Fix rules, reduce correlation windows or restore the database, then requeue. Pausing stops future attempts. Recovery uses current rules, retains action history and does not duplicate completed findings or alerts.'} />
        {feedback && <Alert type={feedback.error ? 'error' : 'success'} message={feedback.text} showIcon closable onClose={() => setFeedback(undefined)} />}
        {query.error && <Alert type="error" message={query.error instanceof Error ? query.error.message : String(query.error)} showIcon />}
        <Space wrap>
          <Select aria-label="Analysis recovery state" style={{ width: 160 }} value={filter}
            options={Object.entries(labels).map(([value, label]) => ({ value, label }))}
            onChange={value => { setFilter(value); setPage(1); }} />
          <Input.Search placeholder={zh ? '事件 ID / 错误代码' : 'Event ID / error code'} allowClear maxLength={128}
            onSearch={value => { setSearch(value); setPage(1); }} />
          <Button onClick={() => void query.refetch()}>{zh ? '刷新' : 'Refresh'}</Button>
        </Space>
        <Table<Failure> rowKey="eventId" loading={query.isFetching} dataSource={query.data?.data.items ?? []} scroll={{ x: 1280 }}
          pagination={{ current: page, pageSize: 10, total: query.data?.data.total ?? 0, showSizeChanger: false, onChange: setPage }}
          columns={[
            { title: zh ? '事件与原因' : 'Event and cause', width: 440, render: (_, row) => <Space direction="vertical" size={0}>
              <Typography.Text copyable>{row.eventId}</Typography.Text><Tag>{row.errorCode}</Tag>
              <Typography.Text>{zh ? reasons[row.errorCode] ?? row.lastError : row.lastError}</Typography.Text>
              <EventEvidenceLink reference={`event:${tenant}:${row.eventId}`} /></Space> },
            { title: zh ? '状态' : 'State', dataIndex: 'state', width: 115, render: state => <Tag color={state === 'quarantined' ? 'error' : state === 'resolved' ? 'success' : 'warning'}>{labels[state] ?? state}</Tag> },
            { title: zh ? '本轮 / 累计失败' : 'Cycle / total failures', width: 130, render: (_, row) => `${row.attempts} / ${row.totalAttempts}` },
            { title: zh ? '最近更新 / 下次尝试' : 'Updated / next attempt', width: 225, render: (_, row) => <Space direction="vertical" size={0}>
              <span>{new Date(row.updatedAt).toLocaleString()}</span><span>{row.availableAt ? new Date(row.availableAt).toLocaleString() : '—'}</span></Space> },
            { title: zh ? '操作' : 'Actions', width: 320, render: (_, row) => <Space wrap>
              <Button size="small" disabled={!!busy || !query.data?.data.canManage || row.state === 'resolved'}
                onClick={() => void act(row, 'retry')}>{zh ? '重新排队' : 'Requeue'}</Button>
              <Button size="small" disabled={!!busy || !query.data?.data.canManage || row.state === 'resolved' || row.state === 'paused'}
                onClick={() => void act(row, 'pause')}>{zh ? '暂停重试' : 'Pause retries'}</Button>
              <Button size="small" onClick={() => { setHistory(row.eventId); setHistoryPage(1); }}>{zh ? '恢复历史' : 'Recovery history'}</Button>
            </Space> },
          ]} />
        {history && <><Typography.Title level={5}>{zh ? '恢复历史' : 'Recovery history'} · {history}</Typography.Title>
          {log.error && <Alert type="error" message={log.error instanceof Error ? log.error.message : String(log.error)} />}
          <Table<HistoryItem> rowKey="id" loading={log.isFetching} dataSource={log.data?.data.items ?? []}
            pagination={{ current: historyPage, pageSize: 10, total: log.data?.data.total ?? 0, onChange: setHistoryPage, showSizeChanger: false }}
            columns={[
              { title: zh ? '操作' : 'Action', dataIndex: 'action', render: value => value === 'retry' ? (zh ? '重新排队' : 'Requeue') : (zh ? '暂停重试' : 'Pause retries') },
              { title: zh ? '操作者' : 'Actor', dataIndex: 'actorId' },
              { title: zh ? '原版本' : 'Previous version', dataIndex: 'previousVersion' },
              { title: zh ? '时间' : 'Time', dataIndex: 'createdAt', render: value => new Date(value).toLocaleString() },
            ]} /></>}
      </Space>
    </Drawer>
  </>;
}
