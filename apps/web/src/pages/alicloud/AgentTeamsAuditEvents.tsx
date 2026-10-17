import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Button, Descriptions, Space, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { AgentTeamsAuditEvent } from '@/types/agentTeamsAudit';

export default function AgentTeamsAuditEvents({ items, onTrace }: {
  items: AgentTeamsAuditEvent[]; onTrace?: (traceId: string, recordId: string) => void;
}) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const kinds = { call: text('调用', 'Call'), message: text('消息', 'Message'), task: text('任务', 'Task'), heartbeat: text('心跳', 'Heartbeat') };
  const endpoint = (team?: string | null, worker?: string | null, assetId?: string | null) => <Space direction="vertical" size={0}>
    <span>{team ?? '—'}</span>
    {assetId ? <Link to={`/assets/${encodeURIComponent(assetId)}`}>{worker ?? assetId}</Link> : <Typography.Text type="secondary">{worker ?? '—'}</Typography.Text>}
  </Space>;
  const columns: ColumnsType<AgentTeamsAuditEvent> = [
    { title: text('事件时间', 'Event time'), dataIndex: 'eventTime', width: 200 },
    { title: text('类型 / 来源', 'Kind / source'), width: 200, render: (_, row) => <Space direction="vertical" size={0}>
      <Space><Tag>{kinds[row.kind]}</Tag>{row.mocked && <Tag color="blue">Mock</Tag>}</Space>
      <span>{row.sourceName ?? row.sourceId}</span>
    </Space> },
    { title: text('发送方', 'From'), width: 190, render: (_, row) => endpoint(row.fromTeam, row.fromWorker, row.fromAssetId) },
    { title: text('接收方', 'To'), width: 190, render: (_, row) => endpoint(row.toTeam, row.toWorker, row.toAssetId) },
    { title: text('状态 / 耗时', 'Status / duration'), width: 130, render: (_, row) => <Space direction="vertical" size={0}>
      <span>{row.status ?? '—'}</span><span>{row.durationMs === undefined || row.durationMs === null ? '—' : `${row.durationMs} ms`}</span>
    </Space> },
    { title: text('脱敏消息预览', 'Redacted message preview'), dataIndex: 'messagePreview', width: 290,
      render: (value?: string) => <span style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{value || '—'}</span> },
    { title: 'Trace / Span', width: 300, render: (_, row) => <Space direction="vertical" size={0}>
      <Typography.Text copyable={!!row.traceId}>{row.traceId ?? '—'}</Typography.Text>
      {row.traceId && onTrace && <Button size="small" onClick={() => onTrace(row.traceId!, row.id)}>{text('选择 Trace 查询', 'Select Trace query')}</Button>}
      <Typography.Text type="secondary" copyable={!!row.spanId}>{row.spanId ?? '—'}</Typography.Text>
    </Space> },
    { title: text('授权结论', 'Authorization'), width: 110, render: () => <Tag>{text('未知', 'Unknown')}</Tag> },
  ];
  return <Table<AgentTeamsAuditEvent> rowKey="id" size="small" columns={columns} dataSource={items}
    pagination={false} scroll={{ x: 1610 }} expandable={{ expandedRowRender: row => <Descriptions size="small" column={2} items={[
      { key: 'id', label: text('平台记录 ID', 'Record ID'), children: row.id },
      { key: 'event', label: 'Event ID', children: row.eventId },
      { key: 'received', label: text('接收时间', 'Received at'), children: row.receivedAt },
      { key: 'task', label: 'Task ID', children: row.taskId ?? '—' },
      { key: 'parent', label: 'Parent span', children: row.parentSpanId ?? '—' },
      { key: 'authorization', label: text('授权证据', 'Authorization evidence'), children: text('日志尚未提供可验证的授权结论', 'These logs do not establish a verified authorization decision') },
    ]} /> }} />;
}
