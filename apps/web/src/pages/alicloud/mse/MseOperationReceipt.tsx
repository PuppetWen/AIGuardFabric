import { Alert, Button, Descriptions, Popconfirm, Space, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import type { MseOperation } from '@/types/mseInventory';

export default function MseOperationReceipt({ operation, canWrite, busy, cancel }: {
  operation: MseOperation; canWrite: boolean; busy: boolean; cancel: () => void;
}) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Space direction="vertical" size={8} style={{ width: '100%' }}>
    <Space><Tag color={operation.status === 'succeeded' && operation.published ? 'green' : 'default'}>{operation.status}</Tag>
      <Tag color={operation.mocked ? 'blue' : 'orange'}>{operation.mocked ? 'Mock' : 'Live'}</Tag></Space>
    <Descriptions size="small" bordered column={2} items={[
      { key: 'request', label: text('原请求 UUID', 'Original request UUID'), children: <Typography.Text copyable>{operation.requestId}</Typography.Text> },
      { key: 'scope', label: text('来源范围 / 版本', 'Source scope / version'), children: `${operation.scopeId} / ${operation.configurationVersion}` },
      { key: 'location', label: text('地域 / 实例', 'Region / instance'), children: `${operation.region} / ${operation.instanceId}` },
      { key: 'namespace', label: text('命名空间', 'Namespace'), children: operation.namespaceId === '' ? text('默认（空字符串）', 'Default (empty string)') : operation.namespaceId },
      { key: 'pages', label: text('已读页 / 服务', 'Read pages / services'), children: `${operation.pagesRead} / ${operation.servicesObserved}` },
      { key: 'published', label: text('曾发布台账', 'Historical inventory publication'), children: operation.published ? text('是', 'Yes') : text('否', 'No') },
      { key: 'current', label: text('来源仍是当前范围', 'Source is current scope'), children: operation.current ? text('是；不证明最新一轮', 'Yes; not proof of latest run') : text('否；历史回执', 'No; historical receipt') },
      { key: 'archived', label: text('归档 / 原终态', 'Archive / original final status'), children: operation.archived ? `${operation.archivedAt ?? '—'} / ${operation.originalStatus ?? '—'}` : text('未归档', 'Not archived') },
    ]} />
    <Typography.Text>{operation.note}</Typography.Text>
    {operation.canCancel && <Popconfirm title={text('取消原盘点请求？', 'Cancel the original inventory request?')}
      description={text('停止下一页和最终发布；已发出的只读请求不能撤回。', 'Stop subsequent pages and publication; an already-sent read cannot be recalled.')}
      onConfirm={cancel}><Button danger disabled={!canWrite || busy}>{text('取消原请求', 'Cancel original request')}</Button></Popconfirm>}
    {operation.status === 'interrupted' && operation.canCancel && <Alert showIcon type="warning" message={text('租约已过期，但存储记录尚未终态；先显式取消，之后才可归档。',
      'The lease expired but the stored record is not terminal. Cancel explicitly before archiving.')} />}
    {operation.archived && <Alert showIcon type="info" message={text('归档仅整理本地终态台账；原编号只读、永不重新派发，不修改资产或云服务。',
      'Archive organizes the local terminal ledger only. The original ID stays read-only and never dispatches again; assets and cloud services are unchanged.')} />}
  </Space>;
}
