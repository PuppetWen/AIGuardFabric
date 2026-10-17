import { Button, Input, Select, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import type { TraceDraft } from '@/types/agentTeamsTrace';

export default function TraceQueryForm({ draft, edit, query, refresh, loading }: {
  draft: TraceDraft; edit: (patch: Partial<TraceDraft>) => void;
  query: () => void; refresh: () => void; loading: boolean;
}) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Space direction="vertical" size={10} style={{ width: '100%' }}>
    <Space wrap align="end">
      <label>{text('Trace ID', 'Trace ID')}
        <Input aria-label="Trace ID" value={draft.traceId} maxLength={128} placeholder={text('输入真实事件 Trace ID', 'Enter an observed event Trace ID')}
          style={{ width: 320, display: 'block' }} onChange={event => edit({ traceId: event.target.value })} /></label>
      <label>{text('开始时间（UTC）', 'From (UTC)')}
        <Input aria-label={text('Trace 开始时间 UTC', 'Trace from UTC')} type="datetime-local" step={1} value={draft.from}
          style={{ display: 'block' }} onChange={event => edit({ from: event.target.value })} /></label>
      <label>{text('结束时间（UTC，不含）', 'Until (UTC, exclusive)')}
        <Input aria-label={text('Trace 结束时间 UTC', 'Trace until UTC')} type="datetime-local" step={1} value={draft.until}
          style={{ display: 'block' }} onChange={event => edit({ until: event.target.value })} /></label>
      <label>{text('每页事件', 'Events per page')}
        <Select aria-label={text('Trace 每页事件', 'Trace page size')} value={draft.limit} style={{ display: 'block', width: 110 }}
          onChange={limit => edit({ limit })} options={[20, 50, 100, 200].map(value => ({ value, label: String(value) }))} /></label>
      <Button type="primary" aria-label={text('查询 Trace', 'Query Trace')} onClick={query} loading={loading}>{text('查询 Trace', 'Query Trace')}</Button>
      <Button aria-label={text('刷新 Trace 查询', 'Refresh Trace query')} onClick={refresh} disabled={loading}>{text('刷新 Trace 查询', 'Refresh Trace query')}</Button>
    </Space>
    <Typography.Text type="secondary">{text('所有输入按 UTC 解释。起止窗口须为正且≤30天；结束时间不得超过当前时间60秒。最多展示2000个观测节点，不能证明完整业务链。',
      'Inputs are UTC. Use a positive window ≤30 days; the end may be at most 60 seconds in the future. At most 2000 observed nodes are returned; this does not establish a complete business chain.')}</Typography.Text>
  </Space>;
}
