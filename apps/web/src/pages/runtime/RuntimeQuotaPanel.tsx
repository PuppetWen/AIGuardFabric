import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Alert, Button, Form, Input, InputNumber, Popconfirm, Select, Space, Switch, Table, Typography, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { useApiQuery } from '@/api/client';
import { ApiRequestError } from '@/api/transport';
import { runtimeQuotaConfiguration, type RuntimeQuotaDefinition, type RuntimeQuotaDraft, type RuntimeQuotaEntry } from '@/api/runtimeQuotaConfiguration';
import { useSessionAccess } from '@/api/sessionAccess';
import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import { useScopedOperation } from '@/components/useScopedOperation';
import { useAuthStore } from '@/stores/authStore';
import { QuotaIdentity } from './QuotaIdentity';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const wholeNumber = { type: 'integer' as const, min: 0, max: Number.MAX_SAFE_INTEGER };
const fresh = (target = ''): Partial<RuntimeQuotaDraft> => ({ name: '', scope: target ? 'agent' : 'tenant',
  dimension: target ? 'tokens' : 'requests', window: 'day', limit: target ? undefined : 0, action: 'deny', enabled: true, targetId: target });
const draftOf = (quota: RuntimeQuotaDefinition): RuntimeQuotaDraft => ({ name: quota.name, scope: quota.scope,
  dimension: quota.dimension, window: quota.window, limit: quota.limit, softThreshold: quota.softThreshold,
  action: quota.onExceed, enabled: quota.enabled, targetId: quota.targetId ?? '' });

/** Changing organizations discards the old organization's draft and ignores pending completions. */
export function RuntimeQuotaPanel() {
  const access = useSessionAccess();
  const scopeKey = useAuthStore(state => `${state.tenant?.id}:${state.sessionGeneration}`);
  return access.has('quotas:read') ? <ScopedQuotaEditor key={scopeKey} canWrite={access.has('quotas:write')} /> : null;
}

function ScopedQuotaEditor({ canWrite }: { canWrite: boolean }) {
  const [params] = useSearchParams();
  const target = params.get('quota_target') ?? '';
  return <QuotaEditor key={target} target={target} canWrite={canWrite} />;
}

function QuotaEditor({ target, canWrite }: { target: string; canWrite: boolean }) {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const [form] = Form.useForm<RuntimeQuotaDraft>();
  const [editing, setEditing] = useState<RuntimeQuotaDefinition | null>(null);
  const [open, setOpen] = useState(!!target);
  const [page, setPage] = useState(1);
  const [keyword, setKeyword] = useState('');
  const [errorText, setErrorText] = useState('');
  const [conflict, setConflict] = useState(false);
  const operation = useScopedOperation();
  const client = useQueryClient();
  const scope = Form.useWatch('scope', form);
  const rows = useApiQuery('runtime-quota-definitions', () => runtimeQuotaConfiguration.list(page, keyword),
    { key: [page, keyword] });
  const edit = (quota: RuntimeQuotaDefinition | null) => {
    form.resetFields(); form.setFieldsValue(quota ? draftOf(quota) : fresh(target));
    setEditing(quota); setOpen(true); setConflict(false); setErrorText('');
  };
  const save = (values: RuntimeQuotaDraft) => operation.run(async current => {
    if (!canWrite || conflict) return;
    setErrorText('');
    try {
      const saved = await runtimeQuotaConfiguration.save(values, editing?.version ?? 0);
      if (current()) {
        setEditing(saved.data.quota); form.setFieldsValue(draftOf(saved.data.quota));
        void rows.refetch();
        void client.invalidateQueries({ queryKey: ['agf', 'runtime-quotas'] });
        void message.success(zh ? '配额已保存，原有用量保持' : 'Quota saved; existing usage is retained');
      }
    } catch (error) {
      if (current()) {
        setConflict(error instanceof ApiRequestError && error.status === 409);
        setErrorText(error instanceof Error ? error.message : String(error));
      }
    }
  });
  const reload = () => operation.run(async current => {
    try {
      const latest = await runtimeQuotaConfiguration.latest(editing?.name ?? form.getFieldValue('name').trim());
      if (current()) { edit(latest); void rows.refetch(); }
    } catch (error) { if (current()) setErrorText(error instanceof Error ? error.message : String(error)); }
  });
  const labels = {
    tenant: zh ? '租户共享' : 'Tenant shared', agent: zh ? '每个 Agent' : 'Per Agent', session: zh ? '每个会话' : 'Per session',
    requests: zh ? '请求次数' : 'Requests', tokens: 'Token', concurrency: zh ? '未完成并发' : 'In-flight calls', cost: zh ? '金额（微元）' : 'Cost (micro units)',
    minute: zh ? '分钟' : 'Minute', hour: zh ? '小时' : 'Hour', day: zh ? 'UTC 日' : 'UTC day', month: zh ? 'UTC 月' : 'UTC month', total: zh ? '总计' : 'Total',
    deny: zh ? '拒绝' : 'Deny', throttle: zh ? '限流拒绝' : 'Throttle', quota: zh ? '超额拒绝' : 'Quota deny', audit: zh ? '观察计量' : 'Observe', allow: zh ? '允许并计量' : 'Allow and meter',
  };
  const options = (values: (keyof typeof labels)[]) => values.map(value => ({ value, label: labels[value] }));
  const validVersion = !editing || (Number.isSafeInteger(editing.version) && editing.version >= 0);
  return <section id="quota-rules">
    <Panel title={zh ? '运行时配额规则' : 'Runtime quota rules'} extra={<Space>
      <Button onClick={() => void rows.refetch()} disabled={operation.busy}>{zh ? '刷新规则' : 'Refresh rules'}</Button>
      {canWrite && <Button onClick={() => edit(null)} disabled={operation.busy}>{zh ? '新建配额' : 'Create quota'}</Button>}
    </Space>}>
      <Alert showIcon type="info" message={zh ? '管理 MCP 与模型调用的通用额度' : 'Manage generic MCP and model call quotas'}
        description={zh ? '先选择作用域、维度与窗口；只限制一个 Worker 时填其 Agent 资产 ID。已有规则可调整额度、动作或启停，保存保留已用量；0 表示本地不设上限，不会阻止调用。云端 Worker 绑定仍须正额度。与“设置 → 网关配额”分别管理。'
          : 'Choose a scope, dimension and window. For one Worker, enter its Agent asset ID. Edit limits, actions or enablement while retaining usage; 0 sets no local limit and does not block calls. Cloud Worker binding still requires a positive limit. Gateway defaults are managed separately in Settings.'} />
      <Input.Search aria-label={zh ? '搜索配额规则' : 'Search quota rules'} placeholder={zh ? '按名称搜索' : 'Search by name'}
        style={{ margin: '12px 0' }} allowClear onSearch={value => { setKeyword(value); setPage(1); }} />
      <DataState loading={rows.isLoading} error={rows.error}>
        <Table<RuntimeQuotaEntry> size="small" rowKey={row => row.quota.id} dataSource={rows.data?.data.items ?? []}
          pagination={{ current: page, pageSize: 8, total: rows.data?.data.total ?? 0, showSizeChanger: false, onChange: setPage }} columns={[
            { title: zh ? '名称 / 版本' : 'Name / version', render: (_, row) => `${row.quota.name} · v${row.quota.version}` },
            { title: zh ? '配额 UUID / 当前版本' : 'Quota UUID / current revision', render: (_, row) => <QuotaIdentity id={row.quota.id} version={row.quota.version} /> },
            { title: zh ? '范围' : 'Scope', render: (_, row) => <span>{labels[row.quota.scope]}{row.quota.targetId && <small style={{ display: 'block' }}>{row.quota.targetId}</small>}</span> },
            { title: zh ? '维度 / 窗口' : 'Dimension / window', render: (_, row) => `${labels[row.quota.dimension]} / ${labels[row.quota.window]}` },
            { title: zh ? '已用 / 上限' : 'Used / limit', render: (_, row) => `${row.used} / ${row.quota.limit}` },
            { title: zh ? '状态' : 'Status', render: (_, row) => row.quota.enabled ? (zh ? '启用' : 'Enabled') : (zh ? '停用' : 'Disabled') },
            ...(canWrite ? [{ title: zh ? '操作' : 'Actions', render: (_: unknown, row: RuntimeQuotaEntry) => <Button size="small" disabled={operation.busy} onClick={() => edit(row.quota)}>{zh ? '编辑' : 'Edit'}</Button> }] : []),
          ]} />
      </DataState>
      <div hidden={!open || !canWrite}>
        <Typography.Title level={5}>{editing ? (zh ? '编辑配额' : 'Edit quota') : (zh ? '新建配额' : 'Create quota')}</Typography.Title>
        {errorText && <Alert type="error" showIcon message={errorText} description={conflict ? (zh ? '草稿已保留，禁止再次保存旧版本。先复制需保留的修改，再确认加载最新规则并人工合并。'
          : 'Your draft is retained and stale retries are blocked. Copy your changes before confirming a reload, then merge manually.') : undefined} />}
        {conflict && <Popconfirm title={zh ? '丢弃草稿并加载最新规则？' : 'Discard this draft and load the latest rule?'} onConfirm={() => void reload()}>
          <Button disabled={operation.busy} style={{ marginTop: 10 }}>{zh ? '加载最新规则' : 'Load latest rule'}</Button>
        </Popconfirm>}
        {!validVersion && <Alert type="error" message={zh ? '配置版本无效，请刷新核对' : 'Invalid configuration version; reload to verify'} />}
        <Form<RuntimeQuotaDraft> form={form} layout="vertical" initialValues={fresh(target)} disabled={operation.busy || !canWrite}
          onFinish={values => void save(values)} style={{ marginTop: 12 }}>
          <div className="agf-grid" style={{ gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))' }}>
            <Form.Item name="name" label={zh ? '配额名称' : 'Quota name'} rules={[{ required: true, whitespace: true, max: 128 }]}><Input disabled={operation.busy || !!editing} /></Form.Item>
            <Form.Item name="scope" label={zh ? '作用域' : 'Scope'} rules={[{ required: true }]}><Select disabled={operation.busy || !!editing} options={options(['tenant', 'agent', 'session'])} /></Form.Item>
            <Form.Item name="dimension" label={zh ? '计量维度' : 'Dimension'} rules={[{ required: true }]}><Select disabled={operation.busy || !!editing} options={options(['requests', 'tokens', 'concurrency', 'cost'])} /></Form.Item>
            <Form.Item name="window" label={zh ? '时间窗口' : 'Window'} rules={[{ required: true }]}><Select disabled={operation.busy || !!editing} options={options(['minute', 'hour', 'day', 'month', 'session', 'total'])} /></Form.Item>
            <Form.Item name="targetId" label={zh ? 'Agent 资产 ID（留空应用于每个 Agent）' : 'Agent asset ID (empty applies to each Agent)'}
              rules={[{ validator: async (_, value: string | undefined) => {
                if (scope === 'agent' && value?.trim() && !uuid.test(value.trim())) throw new Error(zh ? '请输入有效的 Agent UUID' : 'Enter a valid Agent UUID');
              } }]}><Input disabled={operation.busy || !!editing || scope !== 'agent'} /></Form.Item>
            <Form.Item name="limit" label={zh ? '额度上限（0 本地不限）' : 'Limit (0 sets no local limit)'} rules={[{ required: true }, wholeNumber,
              { validator: async (_, value: number) => { if (target && value <= 0) throw new Error(zh ? 'Worker 绑定需要填写正额度' : 'Worker binding requires a positive limit'); } }]}><InputNumber min={0} max={Number.MAX_SAFE_INTEGER} precision={0} style={{ width: '100%' }} /></Form.Item>
            <Form.Item name="softThreshold" label={zh ? '软阈值（留空为上限 80%）' : 'Soft threshold (empty defaults to 80%)'} rules={[wholeNumber, { validator: async (_, value: number | null | undefined) => {
              if (value !== null && value !== undefined && value > form.getFieldValue('limit')) throw new Error(zh ? '软阈值不能超过上限' : 'Soft threshold cannot exceed the limit');
            } }]}><InputNumber min={0} max={Number.MAX_SAFE_INTEGER} precision={0} style={{ width: '100%' }} /></Form.Item>
            <Form.Item name="action" label={zh ? '超限动作' : 'On exceed'} rules={[{ required: true }]}><Select options={options(['deny', 'throttle', 'quota', 'audit', 'allow'])} /></Form.Item>
            <Form.Item name="enabled" label={zh ? '启用规则' : 'Enabled'} valuePropName="checked"><Switch /></Form.Item>
          </div>
          <Space><Button type="primary" htmlType="submit" loading={operation.busy} disabled={conflict || !validVersion || !canWrite}>{zh ? '保存配额' : 'Save quota'}</Button>
            <Button disabled={operation.busy} onClick={() => setOpen(false)}>{zh ? '关闭编辑' : 'Close editor'}</Button></Space>
        </Form>
      </div>
    </Panel>
  </section>;
}
