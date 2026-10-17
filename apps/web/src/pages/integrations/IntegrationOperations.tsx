import { newRequestId } from '@/utils/requestId';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Form, Input, Select, Space, Table, Tag, Typography } from 'antd';
import { integrationsApi, matchesReceipt, receiptSucceeded, type IntegrationConfig, type IntegrationRun } from '@/api/integrations';
import { useAuthStore } from '@/stores/authStore';
import { useSessionAccess } from '@/api/sessionAccess';
import { OperationReceipt } from '@/components/receipts/OperationReceipt';
import { ReceiptRecoveryGuide } from '@/components/receipts/ReceiptRecoveryGuide';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { pushExample, resources } from './fields';

export default function IntegrationOperations({ snapshot }: { snapshot: IntegrationConfig }) {
  const tenantId = useAuthStore(state => state.tenant?.id);
  const generation = useAuthStore(state => state.sessionGeneration);
  const scope = `${tenantId}:${generation}:${snapshot.name}:${snapshot.version}:${snapshot.enabled}:${snapshot.mock}:${snapshot.environmentMock}`;
  return <ScopedIntegrationOperations key={scope} snapshot={snapshot} />;
}

function ScopedIntegrationOperations({ snapshot }: { snapshot: IntegrationConfig }) {
  const { t, i18n } = useTranslation();
  const scope = useOperationScope();
  const access = useSessionAccess();
  const canInspect = access.has('integrations:write');
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [form] = Form.useForm();
  const mocked = snapshot.mock || snapshot.environmentMock;
  const edrLive = snapshot.name === 'edr-isolation' && !mocked;
  const iamLive = snapshot.name === 'iam-scim' && !mocked;
  const [operation, setOperation] = useState(edrLive ? 'pull' : 'send');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<IntegrationRun>();
  const [history, setHistory] = useState<IntegrationRun[]>([]);
  const [confirmed, setConfirmed] = useState(false);
  const [requestId, setRequestId] = useState(() => newRequestId());
  const pending = useRef<unknown>(null);
  const supports = edrLive ? ['pull'] : iamLive ? [] : ['send', ...['push', 'pull', 'sync'].filter(key => snapshot.metadata.semantics[key] === 'implemented')];
  const refresh = async (generation: number) => {
    if (!scope.current(generation)) return;
    const response = await integrationsApi.history(snapshot.name);
    if (scope.current(generation)) setHistory(response.data.items);
  };
  useEffect(() => {
    const generation = scope.checkpoint();
    void integrationsApi.history(snapshot.name).then(response => { if (scope.current(generation)) setHistory(response.data.items); })
      .catch(cause => { if (scope.current(generation)) setError(String(cause)); });
  }, [snapshot.name, scope]);
  const reset = () => {
    if (!scope.reset()) return;
    pending.current = null; setRequestId(newRequestId()); setResult(undefined); setConfirmed(false); setError('');
  };
  const execute = async () => {
    if (!canInspect) return;
    const generation = scope.begin();
    if (generation === undefined) return;
    setBusy(true); setError('');
    try {
      const values = await form.validateFields();
      if (!scope.current(generation)) return;
      let payload: unknown;
      if (operation === 'send') {
        payload = { kind: ['edr-isolation', 'iam-scim'].includes(snapshot.name) ? 'event' : 'notification',
          event_type: snapshot.name === 'edr-isolation' ? 'enforce.isolate' : snapshot.name === 'iam-scim' ? 'enforce.deactivate-user' : 'notify.alert',
          title: values.title, summary: values.summary ?? '', severity: values.severity,
          idempotency_key: requestId, occurred_at: new Date().toISOString(), body: {},
          labels: snapshot.name === 'edr-isolation' ? { host_id: values.host, action: 'isolate' }
            : snapshot.name === 'iam-scim' ? { user_id: values.user, action: 'deactivate' } : {} };
      } else payload = JSON.parse(values.payload);
      pending.current ??= { request_id: requestId, configuration_version: snapshot.version, confirm_live: confirmed, operation, payload };
      const response = await integrationsApi.execute(snapshot.name, pending.current);
      if (!scope.current(generation)) return;
      setResult(response.data);
      await refresh(generation);
    } catch (cause) {
      if (scope.current(generation) && cause instanceof Error) setError(cause.message);
    } finally { if (scope.finish(generation)) setBusy(false); }
  };
  const refreshHistory = async () => {
    const generation = scope.begin();
    if (generation === undefined) return;
    setBusy(true); setError('');
    try { await refresh(generation); }
    catch (cause) { if (scope.current(generation)) setError(String(cause)); }
    finally { if (scope.finish(generation)) setBusy(false); }
  };
  const readReceipt = async (id: string, recover = false) => {
    if (!canInspect) return;
    if (recover && (result?.id !== id || result.completionState !== 'pending_audit')) return;
    const generation = scope.begin();
    if (generation === undefined) return;
    setBusy(true); setError('');
    try {
      const response = await (recover ? integrationsApi.recover(snapshot.name, id) : integrationsApi.receipt(snapshot.name, id));
      if (!scope.current(generation)) return;
      if (!matchesReceipt(response.data, snapshot.name, id)) throw new Error(t('receipt.identityMismatch'));
      setResult(response.data);
      if (recover) setHistory(rows => rows.map(row => row.id === id ? response.data : row));
    } catch (cause) { if (scope.current(generation)) setError(String(cause)); }
    finally { if (scope.finish(generation)) setBusy(false); }
  };
  return <Space direction="vertical" size="middle" style={{ width: '100%' }}>
    <Alert type={mocked ? 'info' : 'warning'} showIcon message={iamLive
      ? text('SCIM 真实身份停用只能通过案件审批', 'Live SCIM identity deactivation requires case approval')
      : edrLive
      ? text('EDR 真实隔离只能通过案件审批；此处仅开放读取', 'Live EDR isolation requires case approval; this page only reads')
      : mocked ? text('模拟业务调用：不会发送消息或修改外部系统', 'Mock operation: no messages or external changes')
        : text('实际业务调用：会读取外部数据、发送消息或变更指定对象', 'Live operation: reads data, delivers messages or updates selected objects')}
      description={iamLive
        ? text('到案件中心关联已绑定 SCIM 用户的凭据资产，提交身份停用并审批。此处可查看调用回执；Mock 模式可测试集成编码。',
          'Link a credential asset bound to a SCIM user in Cases, submit deactivation and approve. Review receipts here; Mock mode tests encoding.')
        : edrLive
        ? text('到案件中心关联资产并提交“通过 EDR 隔离主机”，核对绑定编号后审批。这里可读取 EDR 主机清单；Mock 模式可演练集成调用。',
          'Link an asset in Cases, submit EDR host isolation and approve after checking its binding. You can read EDR hosts here; Mock mode can exercise integration calls.')
        : text('发送用于新建通知或工单；回写必须填写已有对象编号；读取结果显示在回执中，同步按所提供快照对账。此面板不自动触发告警通知。',
          'Send creates a message or ticket. Push requires an existing object ID. Pull returns records; sync reconciles the supplied snapshots. This panel does not configure automatic alert delivery.')} />
    {!iamLive && <Form form={form} layout="vertical" disabled={busy} initialValues={{ severity: 'medium',
      payload: edrLive ? JSON.stringify({ resource: 'hosts', limit: 100 }, null, 2) : undefined }} onValuesChange={reset}>
      <Form.Item label={text('操作', 'Operation')}><Select value={operation} options={supports.map(value => ({ value,
        label: ({ send: text('发送 / 创建', 'Send / create'), push: text('回写状态', 'Push update'), pull: text('增量读取', 'Pull records'), sync: text('快照对账', 'Reconcile snapshots') } as Record<string, string>)[value] }))}
        onChange={value => {
          setOperation(value); reset();
          form.setFieldValue('payload', JSON.stringify(value === 'push' ? pushExample(snapshot.name) : {
            resource: resources[snapshot.name] ?? 'events', limit: 100, ...(value === 'sync' ? { local: [], conflict_policy: 'external-wins' } : {}),
          }, null, 2));
        }} /></Form.Item>
      {operation === 'send' ? <>
        <Form.Item name="title" label={text('标题', 'Title')} rules={[{ required: true }]}><Input maxLength={250} /></Form.Item>
        <Form.Item name="summary" label={text('内容 / 处置原因', 'Content / reason')}><Input.TextArea rows={3} maxLength={10000} /></Form.Item>
        <Form.Item name="severity" label={text('严重级别', 'Severity')}><Select options={['info', 'low', 'medium', 'high', 'critical'].map(value => ({ value }))} /></Form.Item>
        {snapshot.name === 'edr-isolation' && <Form.Item name="host" label={text('目标 EDR 主机编号', 'Target EDR host ID')} rules={[{ required: true }]}><Input /></Form.Item>}
        {snapshot.name === 'iam-scim' && <Form.Item name="user" label={text('目标 SCIM 用户编号', 'Target SCIM user ID')} rules={[{ required: true }]}><Input /></Form.Item>}
      </> : <Form.Item name="payload" label={text('请求内容 JSON', 'Request JSON')} rules={[{ required: true }]}><Input.TextArea rows={10} spellCheck={false} /></Form.Item>}
    </Form>}
    {!iamLive && !mocked && <Checkbox checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)}>
      {text('我已核对目标和内容，执行本次真实调用', 'I verified the target and content and intend this live operation')}</Checkbox>}
    <Space wrap>{!iamLive && <Button type="primary" loading={busy} disabled={!canInspect || !snapshot.enabled || !!result || (!mocked && !confirmed)} onClick={() => void execute()}>
      {mocked ? text('执行模拟调用', 'Run mock operation') : text('执行业务调用', 'Run live operation')}</Button>}
      {!iamLive && <Button disabled={busy} onClick={reset}>{text('新建调用', 'New operation')}</Button>}
      <Button disabled={busy} onClick={() => void refreshHistory()}>{text('刷新记录', 'Refresh history')}</Button></Space>
    {!iamLive && <Typography.Text type="secondary">{text('请求编号', 'Request ID')}: {requestId}</Typography.Text>}
    {error && <Alert type="error" message={error} description={t('receipt.errorHint')} />}
    {result && <><Alert type={receiptSucceeded(result) ? 'success' : result.status === 'failed' ? 'error' : 'warning'} message={`${result.mocked ? text('模拟', 'Mock') : text('真实', 'Live')} · ${result.status}`}
      description={canInspect ? <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', maxHeight: 360, overflow: 'auto' }} copyable>{JSON.stringify(result.receipt, null, 2)}</Typography.Paragraph> : undefined} />
      <OperationReceipt run={result} permission="integrations:write" canWrite={canInspect} busy={busy}
        onRead={() => void readReceipt(result.id)} onRecover={() => void readReceipt(result.id, true)} /></>}
    <ReceiptRecoveryGuide />
    {!canInspect && <Typography.Text type="secondary">{t('receipt.inspectPermission', { permission: 'integrations:write' })}</Typography.Text>}
    <Table size="small" rowKey="id" pagination={{ pageSize: 5 }} dataSource={history} columns={[
      { title: text('时间', 'Time'), dataIndex: 'startedAt', render: value => new Date(value as string).toLocaleString() },
      { title: text('操作', 'Operation'), dataIndex: 'operation' },
      { title: text('结果', 'Result'), render: (_, row) => <Space><Tag>{row.status}</Tag>{row.mocked && <Tag>Mock</Tag>}
        {row.completionState === 'pending_audit' && <><Tag>pending_audit</Tag>
          <Typography.Text type="secondary">{t('receipt.provider')}: {row.providerStatus ?? 'unknown'}</Typography.Text></>}</Space> },
      { title: text('回执', 'Receipt'), render: (_, row) => <Button size="small" disabled={busy || !canInspect}
        onClick={() => void readReceipt(row.id)}>{text('查看', 'View')}</Button> },
    ]} />
  </Space>;
}
