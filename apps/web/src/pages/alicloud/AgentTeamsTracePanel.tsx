import { Alert, Button, Collapse, Descriptions, Space, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import type { TraceSelection } from '@/types/agentTeamsTrace';
import AgentTeamsAuditEvents from './AgentTeamsAuditEvents';
import TraceEvidenceGraph from './trace/TraceEvidenceGraph';
import TraceQueryForm from './trace/TraceQueryForm';
import TraceGuide from './trace/TraceGuide';
import { useAgentTeamsTrace } from './trace/useAgentTeamsTrace';

export default function AgentTeamsTracePanel({ selection }: { selection?: TraceSelection }) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const access = useSessionAccess();
  const tenant = useAuthStore(state => state.tenant);
  const generation = useAuthStore(state => state.sessionGeneration);
  return <Panel title={zh ? 'Trace 观测查询' : 'Trace observation query'}>
    <DataState loading={access.isLoading} error={access.error}>
      {!access.has('alicloud:read') || !access.has('sources:read')
        ? <Alert type="info" showIcon message={zh ? '查看 Trace 需要 alicloud:read 和 sources:read 权限。' : 'Viewing Trace requires alicloud:read and sources:read.'} />
        : <TraceContent key={`${tenant?.id ?? 'none'}:${tenant?.slug ?? ''}:${generation}:${selection?.revision ?? 0}`} selection={selection} />}
    </DataState>
  </Panel>;
}

function TraceContent({ selection }: { selection?: TraceSelection }) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const query = useAgentTeamsTrace(selection?.traceId);
  const data = query.data;
  return <Space direction="vertical" size={12} style={{ width: '100%' }}>
    {selection && <Typography.Text type="secondary">{text('已选中真实审计记录', 'Selected actual audit record')}: {selection.recordId}. {text('核对时间窗后人工查询。', 'Review the window, then query explicitly.')}</Typography.Text>}
    <TraceQueryForm draft={query.draft} edit={query.edit} query={query.query} refresh={query.refresh} loading={query.loading} />
    <Collapse items={[{ key: 'guide', label: text('Trace 操作与 SDK 接入指南', 'Trace operations and SDK onboarding guide'), children: <TraceGuide /> }]} />
    {query.error && <Alert showIcon type="error" message={query.conflict
      ? text('记录或云范围已改变（409）；旧结果保留，停止翻页。点击“刷新 Trace 查询”重新建立快照。', 'Records or cloud scope changed (409). The saved result remains; paging stopped. Use Refresh Trace query to start a new snapshot.')
      : query.error} />}
    {!data && !query.loading && <Alert type="info" showIcon message={text('尚未查询。填写真实 Trace ID 后点击查询；不自动生成演示链路。', 'No query yet. Enter an actual Trace ID and query; no demo trace is generated.')} />}
    {data && <>
      {query.loading && <Alert type="info" message={text('新查询进行中，当前显示保存的结果。', 'A query is running; the saved result is shown.')} />}
      <Descriptions size="small" column={2} items={[
        { key: 'trace', label: 'Trace ID', children: data.traceId },
        { key: 'scope', label: text('云范围 / 版本', 'Cloud scope / version'), children: `${data.scopeId ?? '—'} / ${data.cloudVersion}` },
        { key: 'window', label: text('实际查询时间窗 UTC', 'Actual UTC query window'), children: `${data.windowFrom} — ${data.windowTo}` },
        { key: 'watermark', label: text('接收水位', 'Receive watermark'), children: data.asOfReceivedAt },
        { key: 'total', label: text('窗口事件数', 'Window event count'), children: data.totalEvents === null ? text('未知（盘点不可用）', 'Unknown (inventory unavailable)') : data.totalEvents },
        { key: 'mock', label: text('模式与授权', 'Mode and authorization'), children: <Space>{data.mocked === true && <Tag color="blue">Mock</Tag>}
          <Tag>{text('仅已观测；授权未知', 'Observed only; authorization unknown')}</Tag></Space> },
      ]} />
      {!data.inventoryAvailable ? <Alert showIcon type="info" message={text('当前盘点不可用，不能把未知事件数显示为0。完成盘点后人工刷新。', 'Inventory is unavailable; an unknown event count is not zero. Complete inventory and refresh explicitly.')} />
        : data.totalEvents === 0 ? <Alert showIcon type="info" message={text('该范围有效，但当前窗口未观测到此 Trace。不是完整无调用证明。', 'The scope is valid but this Trace was not observed in the window. This is not proof of no calls.')} /> : null}
      <Typography.Text type="secondary">{text('事件页与关系视图分别分页；所有数据仅来自已收到日志，完整性未知。', 'Event and relationship views page independently. All data comes from received logs; coverage is incomplete.')}</Typography.Text>
      <AgentTeamsAuditEvents items={data.items} />
      <Space><Button aria-label={text('Trace 事件上一页', 'Previous Trace event page')} disabled={!query.canBack} onClick={query.back}>{text('上一页事件', 'Previous events')}</Button>
        <span>{text('事件页', 'Event page')} {query.page}</span>
        <Button aria-label={text('Trace 事件下一页', 'Next Trace event page')} disabled={!query.canNext} onClick={query.next}>{text('下一页事件', 'Next events')}</Button></Space>
      <TraceEvidenceGraph graph={data.graph} total={data.totalEvents} truncated={data.truncated} />
    </>}
  </Space>;
}
