import { newRequestId } from '@/utils/requestId';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Collapse, Form, Input, InputNumber, Select, Space, Table, Tag, Typography } from 'antd';
import { cloudApi, type CloudConfig, type CloudContract, type CloudProbe } from '@/api/cloud';
import { matchesReceipt, receiptSucceeded, type IntegrationRun } from '@/api/integrations';
import { useAuthStore } from '@/stores/authStore';
import { useSessionAccess } from '@/api/sessionAccess';
import { OperationReceipt } from '@/components/receipts/OperationReceipt';
import { ReceiptRecoveryGuide } from '@/components/receipts/ReceiptRecoveryGuide';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { actionLabels, initialParameters } from './cloudFields';

export default function CloudOperations({ snapshot }: { snapshot: CloudConfig }) {
  const tenantId = useAuthStore(state => state.tenant?.id);
  const generation = useAuthStore(state => state.sessionGeneration);
  const key = `${tenantId}:${generation}:${snapshot.name}:${snapshot.version}:${snapshot.enabled}:${snapshot.mock}:${snapshot.environmentMock}`;
  return <ScopedCloudOperations key={key} snapshot={snapshot} />;
}

function ScopedCloudOperations({ snapshot }: { snapshot: CloudConfig }) {
  const { t, i18n } = useTranslation();
  const scope = useOperationScope();
  const access = useSessionAccess();
  const canInspect = access.has('alicloud:write');
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [form] = Form.useForm();
  const nativeTeamWrite = (action: string) => snapshot.name.toLowerCase() === 'agentteams' && ['CreateTeam', 'UpdateTeam', 'DeleteTeam'].includes(action);
  const nativeApigWrite = (action: string) => snapshot.name === 'alicloud-apig' && action === 'UpdatePolicy';
  const operations = snapshot.operations.filter(operation => !nativeTeamWrite(operation.action) && !nativeApigWrite(operation.action));
  const [action, setAction] = useState(operations.find(operation => operation.read_only)?.action ?? operations[0]?.action);
  const operation = operations.find(operation => operation.action === action);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<IntegrationRun>();
  const [probe, setProbe] = useState<CloudProbe | undefined>(snapshot.probe);
  const [history, setHistory] = useState<IntegrationRun[]>([]);
  const pending = useRef<unknown>(null);
  useEffect(() => { form.resetFields(); }, [action, form]);
  const mocked = snapshot.mock || snapshot.environmentMock;
  const refresh = async (generation: number) => {
    if (!scope.current(generation)) return;
    const response = await cloudApi.history(snapshot.name);
    if (scope.current(generation)) setHistory(response.data.items);
  };
  useEffect(() => {
    const generation = scope.checkpoint();
    void cloudApi.history(snapshot.name).then(response => { if (scope.current(generation)) setHistory(response.data.items); })
      .catch(cause => { if (scope.current(generation)) setError(String(cause)); });
  }, [snapshot.name, scope]);
  const reset = () => {
    if (!scope.reset()) return;
    pending.current = null; setResult(undefined); setConfirmed(false); setError('');
  };
  const execute = async () => {
    if (!canInspect || !operation || nativeTeamWrite(operation.action) || nativeApigWrite(operation.action)) return;
    const generation = scope.begin();
    if (generation === undefined) return;
    setBusy(true); setError('');
    try {
      const values = await form.validateFields();
      if (!scope.current(generation)) return;
      const parameters: Record<string, unknown> = {};
      for (const parameter of operation.parameters) {
        let value = values[parameter.name];
        if (value === '' || value === undefined || value === null) continue;
        if (['object', 'array'].includes(parameter.schema.type ?? '')) value = JSON.parse(value);
        if (parameter.schema.type === 'boolean') value = value === 'true';
        parameters[parameter.name] = value;
      }
      pending.current ??= { request_id: newRequestId(), configuration_version: snapshot.version, action, parameters, confirm_live: confirmed };
      const response = await cloudApi.execute(snapshot.name, pending.current);
      if (!scope.current(generation)) return;
      setResult(response.data);
      await refresh(generation);
    } catch (cause) { if (scope.current(generation) && cause instanceof Error) setError(cause.message); }
    finally { if (scope.finish(generation)) setBusy(false); }
  };
  const check = async () => {
    if (!canInspect) return;
    const generation = scope.begin();
    if (generation === undefined) return;
    setBusy(true); setError('');
    try {
      const response = await cloudApi.probe(snapshot.name, { configuration_version: snapshot.version, confirm_live: confirmed });
      if (!scope.current(generation)) return;
      setProbe(response.data); await refresh(generation);
    } catch (cause) { if (scope.current(generation)) setError(String(cause)); }
    finally { if (scope.finish(generation)) setBusy(false); }
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
      const response = await (recover ? cloudApi.recover(snapshot.name, id) : cloudApi.receipt(snapshot.name, id));
      if (!scope.current(generation)) return;
      if (!matchesReceipt(response.data, snapshot.name, id)) throw new Error(t('receipt.identityMismatch'));
      setResult(response.data);
      if (recover) setHistory(rows => rows.map(row => row.id === id ? response.data : row));
    } catch (cause) { if (scope.current(generation)) setError(String(cause)); }
    finally { if (scope.finish(generation)) setBusy(false); }
  };
  const field = (parameter: CloudContract['parameters'][number]) => {
    const schema = parameter.schema;
    const complex = ['object', 'array'].includes(schema.type ?? '');
    const control = complex ? <Input.TextArea rows={5} placeholder={schema.type === 'array' ? '[...]' : '{...}'} /> :
      schema.enum?.length ? <Select allowClear options={schema.enum.map(value => ({ value: schema.type === 'integer' ? Number(value) : value, label: String(value) }))} /> :
      schema.type === 'boolean' ? <Select allowClear options={[{ value: 'true', label: 'true' }, { value: 'false', label: 'false' }]} /> :
      ['integer', 'number'].includes(schema.type ?? '') ? <InputNumber style={{ width: '100%' }} precision={schema.type === 'integer' ? 0 : undefined} /> : <Input />;
    return <Form.Item key={parameter.name} name={parameter.name} label={`${parameter.name}${complex ? ' (JSON)' : ''}`} rules={[{ required: schema.required }]}
      extra={complex && schema.properties ? Object.keys(schema.properties).join(', ') : undefined}>{control}</Form.Item>;
  };
  const initial = initialParameters(operation, snapshot);
  const primary = operation?.parameters.filter(parameter => parameter.schema.required || parameter.name in initial || parameter.name === 'body') ?? [];
  const optional = operation?.parameters.filter(parameter => !primary.includes(parameter)) ?? [];
  return <Space direction="vertical" style={{ width: '100%' }} size="middle">
    <Alert type={mocked ? 'info' : 'warning'} showIcon message={mocked ? text('模拟模式：返回测试样本，不会修改云资源', 'Mock mode: example fixtures, no cloud resource changes') : text('真实模式：操作会调用当前配置的云服务', 'Live mode: operations call the configured cloud service')}
      description={text('查询结果保留厂商原始字段和分页令牌。写操作前核对目标；超时或结果不确定时先到云端核对，勿重复提交。', 'Results preserve provider fields and pagination tokens. Verify write targets. Check cloud state after a timeout or uncertain result before issuing another request.')} />
    <Typography.Text copyable>{snapshot.endpoint}</Typography.Text>
    {snapshot.operations.some(operation => nativeApigWrite(operation.action)) && <Alert type="info" showIcon
      message={text('UpdatePolicy 使用专用 APIG 发布流程，不能从通用参数执行器发送。', 'UpdatePolicy uses dedicated APIG publication and cannot be sent from this generic parameter executor.')}
      description={<a href="/alicloud?tab=apig-policy">{text('打开五 ID 绑定、可信预览和原回执', 'Open five-ID binding, trusted previews and original receipts')}</a>} />}
    {snapshot.operations.some(operation => nativeTeamWrite(operation.action)) && <Alert type="info" showIcon
      message={text('团队创建、人员名单修改和删除请使用团队维护。原始参数入口不执行这些写入。', 'Use Team management to create teams, replace members or delete teams. These writes are unavailable in the raw parameter runner.')}
      description={<a href="/alicloud?tab=teams">{text('打开团队维护', 'Open Team management')}</a>} />}
    <Select aria-label={text('云操作', 'Cloud operation')} value={action} disabled={busy} showSearch optionFilterProp="label" style={{ width: '100%' }}
      options={operations.map(operation => ({ value: operation.action, label: `${zh ? (actionLabels[operation.action] ?? operation.action) + ' · ' : ''}${operation.action} (${operation.read_only ? text('只读', 'read') : text('写入', 'write')})` }))}
      onChange={value => { setAction(value); reset(); }} />
    <Form key={action} form={form} layout="vertical" disabled={busy} initialValues={initial} onValuesChange={reset}>
      {primary.map(field)}
      {optional.length > 0 && <Collapse items={[{ key: 'optional', label: text('可选参数与分页', 'Optional parameters and pagination'), children: optional.map(field) }]} />}
    </Form>
    {!mocked && <Checkbox checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)}>{text('已核对地址和参数，确认调用真实云服务', 'I verified the endpoint and parameters and confirm the live call')}</Checkbox>}
    <Space wrap>
      <Button type="primary" loading={busy} disabled={!canInspect || !operation || !snapshot.enabled || (!mocked && !confirmed) || !!result} onClick={() => void execute()}>{text('执行所选操作', 'Run selected operation')}</Button>
      <Button disabled={busy || !canInspect || !snapshot.enabled || (!mocked && !confirmed)} onClick={() => void check()}>{text('运行只读自检', 'Run read-only check')}</Button>
      <Button disabled={busy} onClick={() => void refreshHistory()}>{text('刷新记录', 'Refresh history')}</Button>
      {result && <Button disabled={busy} onClick={reset}>{text('准备新请求', 'Prepare new request')}</Button>}
    </Space>
    {error && <Alert type="error" message={error} description={t('receipt.errorHint')} />}
    {probe && <Alert type={probe.status === 'succeeded' ? 'info' : 'error'} message={`${probe.action}: ${probe.status}`} description={probe.note} />}
    {result && <><Alert type={receiptSucceeded(result) ? 'success' : 'warning'} message={`${result.operation}: ${result.status}`} description={result.requestId} />
      <OperationReceipt run={result} permission="alicloud:write" canWrite={canInspect} busy={busy}
        onRead={() => void readReceipt(result.id)} onRecover={() => void readReceipt(result.id, true)} />
      {canInspect && <pre style={{ maxHeight: 420, overflow: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(result.receipt, null, 2)}</pre>}</>}
    <ReceiptRecoveryGuide />
    <Typography.Title level={5}>{text('最近操作记录', 'Recent operations')}</Typography.Title>
    {!canInspect && <Typography.Text type="secondary">{t('receipt.inspectPermission', { permission: 'alicloud:write' })}</Typography.Text>}
    <Table<IntegrationRun> rowKey="id" size="small" dataSource={history} pagination={{ pageSize: 5 }} columns={[
      { title: text('操作', 'Operation'), dataIndex: 'operation' },
      { title: text('结果', 'Result'), render: (_, row) => <Space><Tag color={receiptSucceeded(row) ? 'green' : 'orange'}>{row.status}</Tag>
        {row.completionState === 'pending_audit' && <><Tag>pending_audit</Tag>
          <Typography.Text type="secondary">{t('receipt.provider')}: {row.providerStatus ?? 'unknown'}</Typography.Text></>}</Space> },
      { title: text('方式', 'Mode'), render: (_, row) => row.mocked ? 'Mock' : 'Live' },
      { title: text('时间', 'Time'), dataIndex: 'startedAt' },
      { title: text('回执', 'Receipt'), render: (_, row) => <Button size="small" disabled={busy || !canInspect}
        onClick={() => void readReceipt(row.id)}>{text('查看', 'View')}</Button> },
    ]} />
  </Space>;
}
