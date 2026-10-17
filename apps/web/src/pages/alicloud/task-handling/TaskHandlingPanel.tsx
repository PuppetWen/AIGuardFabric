import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Collapse, DatePicker, Descriptions, Input, Select, Space, Table, Tag, Typography } from 'antd';
import type { Dayjs } from 'dayjs';
import type { ColumnsType } from 'antd/es/table';
import { useSessionAccess } from '@/api/sessionAccess';
import { Panel } from '@/components/Panel';
import { useAuthStore } from '@/stores/authStore';
import type { HandlingDecision, HandlingEvent } from '@/types/agentTeamsTaskHandling';
import AgentTeamsTracePanel from '../AgentTeamsTracePanel';
import { safeVersion, useTaskHandling } from './useTaskHandling';

export default function TaskHandlingPanel() {
  const tenantId = useAuthStore(state => state.tenant?.id);
  const generation = useAuthStore(state => state.sessionGeneration);
  return <TaskHandlingContent key={`${tenantId ?? 'none'}:${generation}`} />;
}

function TaskHandlingContent() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const access = useSessionAccess();
  const canRead = access.has('alicloud:read') && access.has('sources:read');
  const canWrite = access.has('alicloud:write') && access.has('sources:write');
  const state = useTaskHandling();
  const [showTrace, setShowTrace] = useState(false);
  const [range, setRange] = useState<[Dayjs | null, Dayjs | null] | null>(null);
  const event = state.event;
  const decisions: { value: HandlingDecision; label: string }[] = [
    { value: 'acknowledged', label: text('已确认收到', 'Acknowledged') },
    { value: 'external_action_reported', label: text('已在平台外采取措施', 'External action reported') },
    { value: 'resolved_by_operator', label: text('人工标记已解决', 'Resolved by operator') },
  ];
  const decisionLabel = (decision: HandlingDecision) => decisions.find(item => item.value === decision)?.label ?? decision;
  const columns: ColumnsType<HandlingEvent> = [
    { title: text('事件时间', 'Event time'), dataIndex: 'eventTime', width: 210 },
    { title: text('任务 / 原事件', 'Task / original event'), render: (_, row) => <Space direction="vertical" size={0}>
      <Typography.Text>{row.taskId ?? row.externalEventId}</Typography.Text>
      <Typography.Text type="secondary">{row.messagePreview ?? ''}</Typography.Text>
    </Space> },
    { title: text('来源', 'Source'), render: (_, row) => row.currentSource.sourceName ?? row.sourceId },
    { title: text('处理记录', 'Handling'), render: (_, row) => <Space>
      <Tag>{row.handling ? decisionLabel(row.handling.decision) : text('待人工判断', 'Needs review')}</Tag>
      {row.handling?.archived && <Tag>{text('已归档', 'Archived')}</Tag>}
      {row.mocked && <Tag color="orange">{text('模拟观测', 'Mock observation')}</Tag>}
    </Space> },
    { title: text('操作', 'Actions'), render: (_, row) => <Button disabled={state.busy || Boolean(state.pending && !state.receipt)}
      onClick={() => { setShowTrace(false); void state.select(row.id); }}>{text('查看与处理', 'Inspect and handle')}</Button> },
  ];
  if (!canRead) return <Alert type="info" showIcon message={text('查看需要 alicloud:read 与 sources:read 权限。',
    'Viewing requires alicloud:read and sources:read.')} />;
  const sourceReady = event && !event.currentSource.sourceGone && event.currentSource.fingerprint
    && safeVersion(event.currentSource.cloudConfigurationVersion, true);
  const canAnnotate = Boolean(canWrite && sourceReady && event?.allowedActions.includes('annotate'));
  const canArchive = Boolean(canWrite && event?.allowedActions.includes('archive') && safeVersion(state.page?.generation)
    && (event.currentSource.sourceGone || sourceReady));
  const canRecover = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(state.recoveryId.trim());
  return <Space direction="vertical" size={16} style={{ width: '100%' }}>
    <Alert type="info" showIcon message={text('已收到的错误观测与人工处理', 'Received error observations and operator handling')}
      description={text('来源上报的 error 不代表云厂商确认任务失败。人工标记和归档保存本地处理记录；业务重放尚未提供。',
        'A reported error is an observation, not vendor-confirmed task failure. Annotations and archives are local handling records. Business replay is not available.')} />
    <Collapse items={[{ key: 'guide', label: text('操作指南', 'How to use'), children: <Typography>
      <ol>
        <li>{text('先在消息与调用审计页完成来源绑定，让自己的 Worker 上报实际任务错误，再读取观测列表。',
          'Bind the audit source and have your Worker report actual task errors, then read the observations.')}</li>
        <li>{text('查看原事件、来源和调用链。确认实际情况后，选择人工结论并保存；无需手工填写版本或来源证明。',
          'Inspect the original event, source and trace. Choose and save your operator decision; versions and source proofs are filled automatically.')}</li>
        <li>{text('每次保存生成独立编号。断线或冲突保留草稿及编号，先读取原编号；页面不会自动重派。',
          'Each action gets its own request ID. Disconnects and conflicts retain the draft and ID. Read the original ID; the page never automatically resends.')}</li>
        <li>{text('需要新的处理结论时，先读取原回执，再明确开始新操作、刷新列表和详情。归档只归档本地记录，不修改云任务。',
          'For another decision, read the original receipt, explicitly start a new action, and refresh the list and detail. Archiving affects only local records.')}</li>
        <li>{text('停用来源仍可人工标记；来源已删除时只能归档已有记录。切换组织或账号后需重新读取。',
          'Disabled sources can still be annotated. Removed sources allow archival of existing records only. Re-read after switching organization or account.')}</li>
      </ol>
    </Typography> }]} />
    {state.error && <Alert type="error" showIcon message={state.error} description={text('草稿与原请求保持不变，请先核对原回执及当前版本。',
      'The draft and original request are retained. Check its receipt and the current version first.')} />}
    <Panel title={text('错误观测', 'Error observations')}>
      <Space wrap style={{ marginBottom: 12 }}>
        <DatePicker.RangePicker showTime value={range} disabled={state.busy}
          placeholder={[text('开始时间（默认最近24小时）', 'Start (default: past 24 hours)'), text('结束时间', 'End')]}
          onChange={setRange} />
        <Button loading={state.busy} onClick={() => void state.load(false, range?.[0] && range[1]
          ? { from: range[0].toISOString(), until: range[1].toISOString() } : undefined)}>{text('读取 / 刷新列表', 'Read / refresh list')}</Button>
        <Button disabled={state.busy || state.previous.length === 0} onClick={state.back}>{text('上一页', 'Previous page')}</Button>
        <Button disabled={state.busy || !state.page?.nextCursor} onClick={() => void state.load(true)}>{text('下一页', 'Next page')}</Button>
        {state.page && <Typography.Text>{text('本窗口观测数', 'Observations in this window')}: {state.page.total}</Typography.Text>}
      </Space>
      {state.page?.truncated && <Alert type="warning" message={text('已达到 2000 条证据上限，当前列表不是完整错误清单。',
        'The 2,000-record evidence limit was reached. This list is not a complete error inventory.')} />}
      {state.page && <Typography.Paragraph type="secondary">{state.page.windowFrom} — {state.page.windowTo}</Typography.Paragraph>}
      <Table<HandlingEvent> rowKey="id" size="small" columns={columns} dataSource={state.page?.items ?? []}
        pagination={false} scroll={{ x: 900 }} locale={{ emptyText: state.page ? text('本窗口未收到错误观测', 'No error observations in this window')
          : text('尚未读取', 'Not read yet') }} />
    </Panel>
    {event && <Panel title={text('原事件与人工结论', 'Original event and operator decision')}>
      <Descriptions column={1} size="small" items={[
        { key: 'id', label: text('原事件编号', 'Original event ID'), children: <Typography.Text copyable>{event.id}</Typography.Text> },
        { key: 'message', label: text('安全错误摘要', 'Safe error preview'), children: event.messagePreview || text('未提供', 'Not provided') },
        { key: 'worker', label: text('上报 Worker', 'Reporting Worker'), children: event.fromWorker ?? text('未知', 'Unknown') },
        { key: 'source', label: text('来源', 'Source'), children: event.currentSource.sourceName ?? event.sourceId },
        { key: 'source-state', label: text('来源状态', 'Source status'), children: event.currentSource.sourceGone
          ? text('来源已删除，只能归档已有记录', 'Source removed; archive existing records only')
          : event.currentSource.sourceEnabled === true ? text('启用', 'Enabled')
            : event.currentSource.sourceEnabled === false ? text('停用，可保存人工结论', 'Disabled; operator annotations remain available')
              : text('未知，请读取最新详情', 'Unknown; read the latest detail') },
        { key: 'version', label: text('处理版本', 'Handling version'), children: event.handling?.version ?? 0 },
      ]} />
      <Space wrap style={{ marginTop: 12 }}>
        <Select<HandlingDecision> aria-label={text('人工结论', 'Operator decision')} value={state.decision}
          options={decisions} style={{ width: 230 }} disabled={state.busy || Boolean(state.pending) || !canAnnotate}
          onChange={state.setDecision} />
        <Button type="primary" disabled={state.busy || Boolean(state.pending) || !canAnnotate}
          onClick={() => void state.submit('resolve')}>{text('保存人工结论', 'Save operator decision')}</Button>
        <Button disabled={state.busy || Boolean(state.pending) || !canArchive}
          onClick={() => void state.submit('archive')}>{text('归档本地记录', 'Archive local record')}</Button>
        <Button disabled={state.busy} onClick={() => void state.refreshDetail()}>{text('读取最新详情', 'Read latest detail')}</Button>
        <Button disabled={state.busy || !state.canStartNew} onClick={() => void state.newAction()}>{text('明确开始新操作', 'Start a new action')}</Button>
        {event.traceId && <Button onClick={() => setShowTrace(value => !value)}>{text('查看调用链', 'Inspect trace')}</Button>}
      </Space>
      {event.handling?.history.length ? <Collapse style={{ marginTop: 12 }} items={[{ key: 'history', label: text('人工处理历史', 'Operator history'),
        children: event.handling.history.map(row => <Typography.Paragraph key={row.requestId}>
          {row.updatedAt} · v{row.version} · {decisionLabel(row.decision)} · <Typography.Text copyable>{row.requestId}</Typography.Text>
        </Typography.Paragraph>) }]} /> : null}
    </Panel>}
    <Panel title={text('按原请求编号恢复', 'Read the original request')}>
      <Space wrap>
        <Input aria-label={text('原请求编号', 'Original request ID')} maxLength={36} style={{ width: 355 }}
          value={state.recoveryId} onChange={change => state.setRecoveryId(change.target.value)} disabled={state.busy || Boolean(state.pending)} />
        <Button disabled={state.busy || !canRecover} onClick={() => void state.recover()}>{text('只读原回执', 'Read original receipt')}</Button>
      </Space>
      {state.pending && <Typography.Paragraph style={{ marginTop: 10 }}><Typography.Text copyable>{state.pending.id}</Typography.Text></Typography.Paragraph>}
      {state.receipt && <Alert style={{ marginTop: 12 }} type="success" message={text('已读取本地处理回执', 'Local handling receipt received')}
        description={<Space direction="vertical"><Typography.Text copyable>{state.receipt.requestId}</Typography.Text>
          <Typography.Text>{state.receipt.purpose === 'operator-resolution' ? decisionLabel(state.receipt.decision!)
            : text(`本次实际归档 ${state.receipt.changedCount ?? 0} 条`, `${state.receipt.changedCount ?? 0} records archived by this action`)}</Typography.Text>
        </Space>} />}
    </Panel>
    {showTrace && event?.traceId && <AgentTeamsTracePanel key={event.id} selection={{ traceId: event.traceId, recordId: event.id, revision: 1 }} />}
  </Space>;
}
