import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Collapse, Popconfirm, Select, Space, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { agentTeamsAuditApi } from '@/api/agentTeamsAudit';
import { useApiQuery } from '@/api/client';
import { useSessionAccess } from '@/api/sessionAccess';
import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import { useAuthStore } from '@/stores/authStore';
import type { AgentTeamsAuditBinding } from '@/types/agentTeamsAudit';
import type { AgentTeam } from '@/types/domain';
import type { TraceSelection } from '@/types/agentTeamsTrace';
import AgentTeamsAuditEvents from './AgentTeamsAuditEvents';
import AgentTeamsAuditGuide from './AgentTeamsAuditGuide';
import AgentTeamsTracePanel from './AgentTeamsTracePanel';

export default function AgentTeamsAuditPanel({ teams }: { teams: AgentTeam[] }) {
  const tenantId = useAuthStore(state => state.tenant?.id);
  const sessionGeneration = useAuthStore(state => state.sessionGeneration);
  return <AuditContent key={`${tenantId ?? 'none'}:${sessionGeneration}`} teams={teams} />;
}

function AuditContent({ teams }: { teams: AgentTeam[] }) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const access = useSessionAccess();
  const canRead = access.has('sources:read') && access.has('alicloud:read');
  const [selected, setSelected] = useState<string>();
  const [cursor, setCursor] = useState<string>();
  const [previous, setPrevious] = useState<(string | undefined)[]>([]);
  const [revision, setRevision] = useState(0);
  const [busy, setBusy] = useState<string>();
  const [result, setResult] = useState<{ error: boolean; message: string }>();
  const [traceSelection, setTraceSelection] = useState<TraceSelection>();
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const sources = useApiQuery('agentteams-audit-sources', agentTeamsAuditApi.sources, { enabled: canRead });
  const events = useApiQuery('agentteams-audit-events', () => agentTeamsAuditApi.events(cursor),
    { enabled: canRead, key: [cursor, revision] });
  const data = sources.data?.data;
  const selectedId = selected ?? data?.items.find(item => item.state !== 'disabled')?.sourceId ?? data?.sources.find(item => item.enabled)?.id;
  const binding = data?.items.find(item => item.sourceId === selectedId);
  const sourceEnabled = data?.sources.find(item => item.id === selectedId)?.enabled === true;
  const canWrite = !sources.error && data?.canWrite === true && access.has('sources:write') && access.has('alicloud:write');
  const refresh = () => {
    setCursor(undefined); setPrevious([]); setRevision(value => value + 1);
    void sources.refetch();
  };
  const update = async (sourceId: string, version: number, enabled: boolean) => {
    if (!canWrite) return;
    const starting = useAuthStore.getState();
    const current = () => alive.current && useAuthStore.getState().tenant?.id === starting.tenant?.id
      && useAuthStore.getState().sessionGeneration === starting.sessionGeneration;
    setBusy(sourceId); setResult(undefined);
    try {
      await agentTeamsAuditApi.bind(sourceId, version, enabled);
      if (!current()) return;
      setResult({ error: false, message: enabled ? text('绑定已更新；请使用新绑定 ID 更新发送端。', 'Binding updated. Update the sender with the new binding ID.') : text('审计来源已停用。', 'Audit source disabled.') });
      refresh();
    } catch (cause) {
      if (current()) setResult({ error: true, message: cause instanceof Error ? cause.message : String(cause) });
    } finally { if (current()) setBusy(undefined); }
  };
  const states = {
    waiting: { color: 'blue', label: text('等待日志', 'Waiting for logs') },
    active: { color: 'green', label: text('活跃', 'Active') },
    stale: { color: 'orange', label: text('近期未上报', 'Stale') },
    disabled: { color: 'default', label: text('已停用', 'Disabled') },
  };
  const columns: ColumnsType<AgentTeamsAuditBinding> = [
    { title: text('日志源', 'Log source'), dataIndex: 'sourceName', width: 200, render: (name: string, row) =>
      <Space direction="vertical" size={0}><Typography.Link onClick={() => setSelected(row.sourceId)}>{name}</Typography.Link>{row.mocked && <Tag color="blue">Mock</Tag>}</Space> },
    { title: text('状态', 'Status'), width: 120, render: (_, row) => row.state === 'stale' && !row.acceptsEvents
      ? <Tag color="red">{text('绑定失效', 'Invalid binding')}</Tag>
      : <Tag color={states[row.state].color}>{states[row.state].label}</Tag> },
    { title: text('绑定 / 云配置版本', 'Binding / cloud version'), width: 135, render: (_, row) => `${row.version} / ${row.cloudVersion}` },
    { title: text('最近事件', 'Latest event'), dataIndex: 'lastEventAt', width: 210, render: (value?: string) => value ?? text('尚未观测', 'Unobserved') },
    { title: text('24 小时覆盖', '24-hour coverage'), width: 220, render: (_, row) => <Space direction="vertical" size={0}>
      <Tag color={row.completeWindow ? 'green' : 'default'}>{row.completeWindow ? text('完整窗口', 'Complete window') : text('覆盖完整性未知', 'Coverage completeness unknown')}</Tag>
      <Typography.Text type="secondary">{row.coverageStart ? `${text('首个已接收事件', 'First received event')}: ${row.coverageStart}` : text('尚未观测', 'Unobserved')}</Typography.Text>
    </Space> },
    { title: text('操作', 'Actions'), width: 230, render: (_, row) => <Space wrap>
      <Button size="small" onClick={() => setSelected(row.sourceId)}>{text('接入示例', 'Example')}</Button>
      {canWrite && <>
        <Popconfirm title={text('重新绑定当前实例？', 'Rebind to the current instance?')}
          description={text('生成新绑定 ID 并重新开始覆盖窗口；发送端需要更新。', 'A new binding ID starts a new coverage window. Update the sender.')}
          onConfirm={() => update(row.sourceId, row.version, true)}>
          <Button size="small" disabled={!!busy || !data?.inventoryAvailable || !data.sources.some(source => source.id === row.sourceId && source.enabled)}>{text('重新绑定', 'Rebind')}</Button>
        </Popconfirm>
        {row.state !== 'disabled' && <Button size="small" danger disabled={!!busy} loading={busy === row.sourceId}
          onClick={() => void update(row.sourceId, row.version, false)}>{text('停用', 'Disable')}</Button>}
      </>}
    </Space> },
  ];
  return <DataState loading={access.isLoading} error={access.error}>
    {!canRead ? <Alert showIcon type="info" message={text('查看审计需要 sources:read 和 alicloud:read 权限。', 'Viewing audit requires sources:read and alicloud:read.')} /> : <Space direction="vertical" size={14} style={{ width: '100%' }}>
      <Panel title={text('AgentTeams 审计来源', 'AgentTeams audit sources')}>
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Space wrap>
            <Button aria-label={text('刷新审计', 'Refresh audit')} onClick={refresh}
              loading={sources.isFetching || events.isFetching}>{text('刷新审计', 'Refresh audit')}</Button>
            <Select aria-label={text('审计日志源', 'Audit log source')} value={selectedId} onChange={setSelected}
              style={{ minWidth: 260 }} placeholder={text('选择 HTTP Webhook 日志源', 'Select an HTTP Webhook source')}
              options={data?.sources.map(source => ({ value: source.id, label: source.name, disabled: !source.enabled })) ?? []} />
            {canWrite && !binding && <Button type="primary" disabled={!!busy || !selectedId || !sourceEnabled || !data?.inventoryAvailable}
              loading={!!busy} onClick={() => selectedId && void update(selectedId, 0, true)}>{text('绑定所选日志源', 'Bind selected source')}</Button>}
          </Space>
          {result && <Alert type={result.error ? 'error' : 'success'} showIcon message={result.message} />}
          {data && !data.inventoryAvailable && <Alert type="info" showIcon message={text('当前实例尚未完成盘点；请先完成团队同步，再绑定审计来源。', 'Complete inventory for the current instance before binding audit sources.')} />}
          {binding && !binding.acceptsEvents && binding.state !== 'disabled' && <Alert type="info" showIcon
            message={text('当前绑定已失效；完成盘点后重新绑定，并更新发送端绑定 ID。', 'This binding is no longer valid. Complete inventory, rebind and update the sender binding ID.')} />}
          {data && data.items.length === 0 && <Alert type="info" showIcon
            message={text('尚未接入有效审计来源，调用量与授权情况尚未观测。', 'No enabled audit source is connected. Call volume and authorization are unobserved.')} />}
          {data && data.items.length > 0 && data.items.every(item => item.state === 'disabled') && <Alert type="info" showIcon
            message={text('审计来源已停用，新上报已停止。当前窗口的历史事件仍可查看；启用日志源并重新绑定后继续接入。', 'Audit sources are disabled and new ingest has stopped. Historical events remain visible in the current window; enable the source and rebind to resume.')} />}
          <DataState loading={sources.isLoading} error={sources.error} onRetry={() => void sources.refetch()}>
            <Table rowKey="sourceId" size="small" columns={columns} dataSource={data?.items ?? []} pagination={false} scroll={{ x: 1250 }} />
          </DataState>
          <Collapse defaultActiveKey={['guide']} items={[{ key: 'guide', label: text('审计接入指南与可复制示例', 'Audit onboarding and copyable examples'),
            children: <AgentTeamsAuditGuide key={`${revision}:${binding?.bindingId ?? 'none'}`} binding={!sources.error && !sources.isFetching && sourceEnabled && data?.inventoryAvailable ? binding : undefined}
              currentCloudVersion={data?.cloudVersion ?? 0} teams={teams} /> }]} />
        </Space>
      </Panel>
      <Panel title={text('最近 24 小时审计事件', 'Audit events in the last 24 hours')}>
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Typography.Text type="secondary">{text('日志提供调用与消息证据；授权结论未知，不计为未授权调用。', 'Logs provide call and message evidence. Unknown authorization is not counted as unauthorized.')}</Typography.Text>
          {events.data && <Typography.Text type="secondary">{events.data.data.windowFrom} — {events.data.data.windowTo}</Typography.Text>}
          <DataState loading={events.isLoading} error={events.error} onRetry={() => void events.refetch()}>
            {!events.isLoading && !events.error && (events.data?.data.items.length ?? 0) === 0 && <Alert type="info" showIcon
              message={text('当前窗口尚未采集到事件；发送日志后刷新查看。', 'No events have been collected in this window. Send logs, then refresh.')} />}
            <AgentTeamsAuditEvents items={events.data?.data.items ?? []} onTrace={(traceId, recordId) =>
              setTraceSelection(value => ({ traceId, recordId, revision: (value?.revision ?? 0) + 1 }))} />
          </DataState>
          <Space><Button disabled={previous.length === 0 || events.isFetching} onClick={() => {
            setCursor(previous[previous.length - 1]); setPrevious(value => value.slice(0, -1));
          }}>{text('上一页', 'Previous page')}</Button>
            <Button disabled={!events.data?.data.nextCursor || events.isFetching || !!events.error} onClick={() => {
              setPrevious(value => [...value, cursor]); setCursor(events.data?.data.nextCursor ?? undefined);
            }}>{text('下一页', 'Next page')}</Button></Space>
        </Space>
      </Panel>
      <AgentTeamsTracePanel selection={traceSelection} />
    </Space>}
  </DataState>;
}
