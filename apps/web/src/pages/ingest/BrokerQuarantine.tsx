import { useState } from 'react';
import { Alert, Button, Drawer, Input, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useApiQuery } from '@/api/client';
import { callApi } from '@/api/transport';
import { useAuthStore } from '@/stores/authStore';
import { downloadText } from '@/utils/download';

interface MessageRow {
  id: string; stream: string; streamSequence: number; payloadHash: string; payloadBytes: number;
  reasonCode: string; state: string; version: number; createdAt: string; updatedAt: string;
}
interface Evidence { id: string; subject: string; prefix: string; payloadB64: string; payloadHash: string; payloadBytes: number }
interface History { id: string; action: string; actorId: string; note: string; previousVersion: number; createdAt: string }
const base = '/api/v1/sources/broker/quarantine';
const unavailable = () => { throw new Error('Broker quarantine is unavailable'); };

export function BrokerQuarantine({summary}: {summary?: {quarantined: number; retrying: number}}) {
  const tenant = useAuthStore(state => state.tenant?.id);
  return <Queue key={tenant} summary={summary} />;
}

function Queue({summary}: {summary?: {quarantined: number; retrying: number}}) {
  const { i18n } = useTranslation();
  const zh = i18n.language?.startsWith('zh') ?? false;
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState('quarantined');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [historyId, setHistoryId] = useState('');
  const [historyPage, setHistoryPage] = useState(1);
  const [evidence, setEvidence] = useState<Evidence>();
  const [choice, setChoice] = useState<{row: MessageRow; action: 'retry' | 'dismiss'}>();
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<{error: boolean; text: string}>();
  const labels: Record<string, string> = zh
    ? {all: '全部', quarantined: '待处理', retrying: '重试中', resolved: '已交接 / 已完成', dismissed: '已关闭'}
    : {all: 'All', quarantined: 'Needs review', retrying: 'Retrying', resolved: 'Handed off / completed', dismissed: 'Closed'};
  const reasons: Record<string, string> = zh ? {
    invalid_payload: '消息格式无效：修复发布方，通过原接入源重发正确事件。',
    subject_mismatch: '消息主题与租户或等级不符：核对发布方路由。',
    missing_event: '数据库中没有对应原事件：核对来源存储及时间。',
    unknown_tenant: '组织不存在：核对来源组织，不要直接改写消息。',
    retry_interrupted: '人工重试中断：先核对分析回执，再选择处理。',
    routing_or_authorization: '检查原主题路由、组织状态及授权。',
    encryption: '核对原加密密钥，不要替换密钥。',
    dependency_or_analysis: '数据库或分析暂不可用：修复后重试。',
    analysis_completed: '规范数据库事件已完成分析。',
    sql_recovery_owns_retry: '已交给事件分析恢复队列，请在该队列查看结果。',
  } : {
    invalid_payload: 'Invalid event format. Repair the publisher and resubmit through its ingest source.',
    subject_mismatch: 'Subject does not match the event tenant or severity. Fix publisher routing.',
    missing_event: 'Canonical SQL event is missing. Check the original store and timestamp.',
    unknown_tenant: 'Unknown organization. Check the source tenant; do not rewrite evidence.',
    retry_interrupted: 'Manual retry was interrupted. Inspect analysis receipts before acting.',
    routing_or_authorization: 'Check original routing, tenant status and authorization.',
    encryption: 'Check the original encryption key; do not replace it.',
    dependency_or_analysis: 'Database or analysis is unavailable. Repair it before retrying.',
    analysis_completed: 'Canonical SQL event analysis completed.',
    sql_recovery_owns_retry: 'Responsibility transferred to Failed events and recovery; inspect results there.',
  };
  const query = useApiQuery('broker-quarantine', () => callApi<{items: MessageRow[]; total: number; canManage: boolean}>(
    base, unavailable, {noFallback: true, query: {state: filter, q: search, page, page_size: 10}}),
  {enabled: open, key: [filter, search, page], refetchInterval: open ? 15_000 : false});
  const history = useApiQuery('broker-quarantine-history', () => callApi<{items: History[]; total: number}>(
    `${base}/${historyId}/history`, unavailable, {noFallback: true, query: {page: historyPage, page_size: 10}}),
  {enabled: open && !!historyId, key: [historyId, historyPage]});
  const fail = (error: unknown) => setFeedback({error: true, text: error instanceof Error ? error.message : String(error)});
  const inspect = async (row: MessageRow) => {
    setBusy(true); setEvidence(undefined); setFeedback(undefined);
    try {
      const result = await callApi<Evidence>(`${base}/${row.id}`, unavailable, {noFallback: true});
      setEvidence(result.data);
      if (historyId === row.id) void history.refetch();
    } catch (error) { fail(error); } finally { setBusy(false); }
  };
  const act = async () => {
    if (!choice || !reason.trim()) return;
    setBusy(true); setFeedback(undefined);
    try {
      const result = await callApi<{state: string; reasonCode?: string}>(`${base}/${choice.row.id}/${choice.action}`, unavailable,
        {method: 'POST', noFallback: true, timeoutMs: 60_000, body: {expected_version: choice.row.version, reason}});
      setFeedback({error: result.data.state === 'quarantined', text: result.data.reasonCode
        ? reasons[result.data.reasonCode] ?? result.data.reasonCode : (zh ? '已关闭，证据和历史保留。' : 'Closed; evidence and history retained.')});
      if (historyId === choice.row.id) void history.refetch();
      setChoice(undefined); setReason('');
    } catch (error) { fail(error); } finally { setBusy(false); void query.refetch(); }
  };
  return <>
    {summary && (summary.quarantined + summary.retrying > 0) && <Alert showIcon type="warning" message={zh
      ? `全平台异常消息：待处理 ${summary.quarantined} 条，人工重试中 ${summary.retrying} 条`
      : `Global broker quarantine: ${summary.quarantined} awaiting review, ${summary.retrying} retrying`} />}
    <Button onClick={() => setOpen(true)}>{zh ? '平台异常消息与恢复' : 'Platform message quarantine'}</Button>
    <Drawer title={zh ? '平台异常消息与恢复' : 'Platform message quarantine'} open={open} width="min(1400px, 96vw)"
      onClose={() => {setOpen(false); setEvidence(undefined); setHistoryId(''); setFeedback(undefined);}}>
      <Space direction="vertical" style={{width: '100%'}}>
        <Alert showIcon type="info" message={zh ? '全平台队列，仅平台管理员可访问' : 'Global queue — platform administrators only'}
          description={zh ? '消息内的组织信息尚未验证。原文加密保存后才向消息服务确认；确认不代表分析成功。先查原因、修复发布方或恢复原 SQL 事件，再人工重试。重试只读取原始引用对应的规范数据库事件。格式或路由错误应通过接入源重发正确事件，再填写理由关闭此条；关闭保留证据。中断的人工重试需核对，不自动重放。'
            : 'Tenant claims are unverified. Broker ACK follows encrypted evidence persistence and does not mean analysis succeeded. Repair the publisher or restore the original SQL event before retrying. Retries use canonical SQL evidence only. For malformed data or routing, resubmit a corrected event through its source, then close this item with a reason. Evidence is retained; interrupted retries require review.'} />
        {feedback && <Alert showIcon type={feedback.error ? 'error' : 'success'} message={feedback.text} />}
        {query.error && <Alert showIcon type="error" message={String(query.error)} />}
        <Space wrap>
          <Select aria-label={zh ? '异常消息状态' : 'Message quarantine state'} value={filter} style={{width: 210}}
            options={Object.entries(labels).map(([value,label]) => ({value,label}))} onChange={value => {setFilter(value); setPage(1);}} />
          <Input.Search placeholder={zh ? '消息 ID / SHA256 / 原因 / 消息流' : 'Message ID / SHA256 / reason / stream'} maxLength={128} allowClear
            onSearch={value => {setSearch(value); setPage(1);}} />
          <Button onClick={() => void query.refetch()}>{zh ? '刷新' : 'Refresh'}</Button>
        </Space>
        <Table<MessageRow> rowKey="id" dataSource={query.data?.data.items ?? []} loading={query.isFetching} scroll={{x: 1300}}
          pagination={{current: page, pageSize: 10, total: query.data?.data.total ?? 0, showSizeChanger: false, onChange: setPage}}
          columns={[
            {title: zh ? '消息与证据' : 'Message and evidence', width: 340, render: (_,row) => <Space direction="vertical" size={0}>
              <Typography.Text copyable>{row.id}</Typography.Text><span>{row.stream} · #{row.streamSequence} · {row.payloadBytes} B</span>
              <Typography.Text copyable style={{maxWidth: 320}} ellipsis>{row.payloadHash}</Typography.Text></Space>},
            {title: zh ? '原因' : 'Cause', width: 310, render: (_,row) => <><Tag>{row.reasonCode}</Tag><div>{reasons[row.reasonCode] ?? row.reasonCode}</div></>},
            {title: zh ? '状态 / 最近更新' : 'State / updated', width: 210, render: (_,row) => <><Tag>{labels[row.state] ?? row.state}</Tag><div>{new Date(row.updatedAt).toLocaleString()}</div></>},
            {title: zh ? '操作' : 'Actions', width: 420, render: (_,row) => <Space wrap>
              <Button size="small" disabled={busy} onClick={() => void inspect(row)}>{zh ? '查看原始证据' : 'Inspect evidence'}</Button>
              <Button size="small" disabled={busy || !query.data?.data.canManage || row.state !== 'quarantined'} onClick={() => {setChoice({row,action: 'retry'}); setReason(''); setFeedback(undefined);}}>{zh ? '人工重试' : 'Manual retry'}</Button>
              <Button size="small" disabled={busy || !query.data?.data.canManage || row.state !== 'quarantined'} onClick={() => {setChoice({row,action: 'dismiss'}); setReason(''); setFeedback(undefined);}}>{zh ? '关闭并保留证据' : 'Close and retain evidence'}</Button>
              <Button size="small" onClick={() => {setHistoryId(row.id); setHistoryPage(1);}}>{zh ? '处理历史' : 'History'}</Button>
            </Space>},
          ]} />
        {evidence && <><Typography.Title level={5}>{zh ? '原始证据（敏感内容）' : 'Original evidence (sensitive)'}</Typography.Title>
          <Typography.Text copyable>{evidence.subject}</Typography.Text>
          <Typography.Paragraph>{zh ? '原始字节以 Base64 保存，下载后核对 SHA256。查看操作已记录。' : 'Original bytes use Base64. Verify SHA256 after download. This inspection is recorded.'}</Typography.Paragraph>
          <Input.TextArea aria-label={zh ? '原始消息 Base64' : 'Original message Base64'} readOnly value={evidence.payloadB64} autoSize={{minRows: 2,maxRows: 6}} />
          <Space><Button onClick={() => downloadText(`broker-evidence-${evidence.id}.json`,JSON.stringify(evidence,null,2))}>{zh ? '下载证据' : 'Download evidence'}</Button>
            <Button onClick={() => setEvidence(undefined)}>{zh ? '收起原文' : 'Hide evidence'}</Button></Space></>}
        {historyId && <><Typography.Title level={5}>{zh ? '处理历史' : 'History'} · {historyId}</Typography.Title>
          {history.error && <Alert type="error" message={String(history.error)} />}
          <Table<History> rowKey="id" dataSource={history.data?.data.items ?? []} loading={history.isFetching}
            pagination={{current: historyPage, pageSize: 10, total: history.data?.data.total ?? 0, showSizeChanger: false, onChange: setHistoryPage}}
            columns={[{title: zh ? '操作' : 'Action', dataIndex: 'action'}, {title: zh ? '操作者' : 'Actor', dataIndex: 'actorId'},
              {title: zh ? '理由 / 结果' : 'Reason / result', dataIndex: 'note'}, {title: zh ? '原版本' : 'Previous version', dataIndex: 'previousVersion'},
              {title: zh ? '时间' : 'Time', dataIndex: 'createdAt', render: value => new Date(value).toLocaleString()}]} /></>}
      </Space>
    </Drawer>
    <Modal title={choice?.action === 'retry' ? (zh ? '核对后人工重试' : 'Retry after review') : (zh ? '关闭并保留证据' : 'Close and retain evidence')}
      open={!!choice} onCancel={() => {if (!busy) setChoice(undefined);}} onOk={() => void act()} confirmLoading={busy}
      okText={zh ? '确认处理' : 'Confirm action'} cancelText={zh ? '取消' : 'Cancel'} okButtonProps={{disabled: !reason.trim()}}>
      <Typography.Paragraph>{choice?.row.id} · v{choice?.row.version}</Typography.Paragraph>
      <Input.TextArea aria-label={zh ? '处理理由' : 'Action reason'} value={reason} maxLength={1000} onChange={event => setReason(event.target.value)} />
      {feedback?.error && <Alert type="error" showIcon message={feedback.text} />}
    </Modal>
  </>;
}
