import { useState } from 'react';
import { Alert, Button, Form, Input, Popconfirm, Select, Space, Switch, Table, Typography, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { api, useApiQuery } from '@/api/client';
import { callApi } from '@/api/transport';
import { DataState } from '@/components/DataState';
import { useScopedOperation } from '@/components/useScopedOperation';

export interface AgentTargetProfile {
  id: string; assetId: string; name: string; url: string; model: string;
  enabled: boolean; version: number; credentialConfigured: boolean; canaryConfigured: boolean;
}
interface Values {
  name: string; assetId: string; url: string; model: string; enabled: boolean;
  bearerToken?: string; protectedCanary?: string; clearToken?: boolean;
}

export function AgentTargetsPanel({ canConfigure }: { canConfigure: boolean }) {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const [form] = Form.useForm<Values>();
  const [editing, setEditing] = useState<AgentTargetProfile | null>(null);
  const [keyword, setKeyword] = useState('');
  const operation = useScopedOperation();
  const targets = useApiQuery('redteam-agent-targets', () => callApi<{ items: AgentTargetProfile[] }>(
    '/api/v1/redteam/agent-targets', () => ({ items: [] }), { noFallback: true }), {});
  const agents = useApiQuery('redteam-agent-assets', () => api.agents({ page: 1, pageSize: 50, keyword }),
    { key: [keyword], enabled: canConfigure });
  const edit = (profile: AgentTargetProfile | null) => {
    setEditing(profile);
    form.setFieldsValue(profile ? { name: profile.name, assetId: profile.assetId, url: profile.url,
      model: profile.model, enabled: profile.enabled, bearerToken: '', protectedCanary: '', clearToken: false }
      : { name: '', assetId: '', url: '', model: '', enabled: true, bearerToken: '', protectedCanary: '', clearToken: false });
  };
  const save = (values: Values) => operation.run(async current => {
    try {
      const body = { id: editing?.id, expected_version: editing?.version ?? 0, asset_id: values.assetId,
        name: values.name, url: values.url, model: values.model, enabled: values.enabled,
        ...(values.clearToken ? { bearer_token: '' } : values.bearerToken ? { bearer_token: values.bearerToken } : {}),
        ...(values.protectedCanary ? { protected_canary: values.protectedCanary } : {}) };
      await callApi('/api/v1/redteam/agent-targets', () => null, { method: 'POST', body, noFallback: true });
      if (current()) { form.resetFields(); setEditing(null); await targets.refetch(); void message.success(zh ? '目标配置已保存' : 'Target saved'); }
    } catch (error) { if (current()) void message.error(error instanceof Error ? error.message : String(error)); }
  });
  const remove = (profile: AgentTargetProfile) => operation.run(async current => {
    try {
      await callApi(`/api/v1/redteam/agent-targets/${encodeURIComponent(profile.id)}`, () => null,
        { method: 'DELETE', body: { expected_version: profile.version }, noFallback: true });
      if (current()) { if (editing?.id === profile.id) edit(null); await targets.refetch(); }
    } catch (error) { if (current()) void message.error(error instanceof Error ? error.message : String(error)); }
  });
  return <Space direction="vertical" size="middle" style={{ width: '100%' }}>
    <Alert showIcon type="info" message={zh ? '真实 Agent 测试只发送已选攻击提示词' : 'Real Agent tests send only selected attack prompts'}
      description={zh ? '先在被测 Agent 的系统提示词中放入专用哨兵，再把相同哨兵填入这里。端点须从 AIGuardFabric 服务容器可达。令牌与哨兵加密保存，不随列表或报告返回。'
        : 'Put a dedicated canary in the target Agent system prompt, then enter the same value here. The URL must be reachable from the AIGuardFabric server container. Token and canary are encrypted and omitted from lists and reports.'} />
    <DataState loading={targets.isLoading} error={targets.error}>
      <Table rowKey="id" size="small" pagination={{ pageSize: 8 }} dataSource={targets.data?.data.items ?? []} columns={[
        { title: zh ? '目标' : 'Target', dataIndex: 'name' },
        { title: zh ? 'Agent 资产' : 'Agent asset', dataIndex: 'assetId', ellipsis: true },
        { title: zh ? '端点' : 'Endpoint', dataIndex: 'url', ellipsis: true },
        { title: zh ? '版本' : 'Version', dataIndex: 'version' },
        { title: zh ? '状态' : 'Status', render: (_, row: AgentTargetProfile) => row.enabled ? (zh ? '启用' : 'Enabled') : (zh ? '停用' : 'Disabled') },
        { title: zh ? '操作' : 'Actions', render: (_, row: AgentTargetProfile) => canConfigure && <Space>
          <Button size="small" onClick={() => edit(row)}>{zh ? '编辑' : 'Edit'}</Button>
          <Popconfirm title={zh ? '删除这个目标配置？' : 'Delete target profile?'} onConfirm={() => void remove(row)}>
            <Button size="small" danger>{zh ? '删除' : 'Delete'}</Button>
          </Popconfirm>
        </Space> },
      ]} />
    </DataState>
    {canConfigure && <Form<Values> form={form} layout="vertical" disabled={operation.busy} onFinish={values => void save(values)}
      initialValues={{ enabled: true }}>
      <Typography.Title level={5}>{editing ? (zh ? '编辑目标' : 'Edit target') : (zh ? '接入 Agent 目标' : 'Connect Agent target')}</Typography.Title>
      <Form.Item name="name" label={zh ? '配置名称' : 'Profile name'} rules={[{ required: true, whitespace: true }]}>
        <Input maxLength={160} />
      </Form.Item>
      <Input.Search placeholder={zh ? '搜索已纳管 Agent 名称' : 'Search registered Agents'} onSearch={setKeyword} enterButton={zh ? '查找' : 'Search'} />
      <Form.Item name="assetId" label={zh ? '选择已纳管 Agent 资产' : 'Registered Agent asset'} rules={[{ required: true }]}>
        <Select showSearch optionFilterProp="label" loading={agents.isLoading} options={(agents.data?.data.items ?? []).map(agent => ({
          value: agent.id, label: `${agent.name} (${agent.id})`,
        }))} placeholder={zh ? '先在 Agent 管理页纳管，之后在此搜索' : 'Register an Agent first, then search here'} />
      </Form.Item>
      <Form.Item name="url" label={zh ? '聊天端点完整 URL' : 'Full chat endpoint URL'}
        extra={zh ? '例如 https://agent.example/v1/chat/completions；地址不能携带令牌、查询参数或片段。' : 'For example https://agent.example/v1/chat/completions; put credentials in the token field.'}
        rules={[{ required: true, type: 'url' }]}><Input maxLength={2048} /></Form.Item>
      <Form.Item name="model" label={zh ? '端点模型标识' : 'Endpoint model identifier'} rules={[{ required: true, whitespace: true }]}>
        <Input maxLength={160} />
      </Form.Item>
      <Form.Item name="bearerToken" label={editing ? (zh ? '新令牌（留空保留现有）' : 'New token (blank keeps current)') : (zh ? 'Bearer 令牌（可选）' : 'Bearer token (optional)')}>
        <Input.Password autoComplete="off" maxLength={8192} />
      </Form.Item>
      {editing && <Form.Item name="clearToken" valuePropName="checked" label={zh ? '明确清除原令牌' : 'Explicitly clear existing token'}><Switch /></Form.Item>}
      <Form.Item label={zh ? '受保护哨兵' : 'Protected canary'} extra={zh ? '16–128 位字母、数字、下划线或连字符。保存前复制到被测 Agent 的系统提示词；更换目标地址时需重新填写。' : 'Use 16–128 letters, digits, _ or -. Copy it into the target Agent system prompt before saving. Re-enter it when changing the URL.'}>
        <Space.Compact style={{ width: '100%' }}>
          <Form.Item name="protectedCanary" noStyle rules={editing ? [] : [{ required: true }]}><Input autoComplete="off" maxLength={128} /></Form.Item>
          <Button onClick={() => form.setFieldValue('protectedCanary', Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join(''))}>{zh ? '生成' : 'Generate'}</Button>
        </Space.Compact>
      </Form.Item>
      <Form.Item name="enabled" label={zh ? '允许执行' : 'Enabled'} valuePropName="checked"><Switch /></Form.Item>
      <Space><Button type="primary" htmlType="submit" loading={operation.busy}>{zh ? '保存配置' : 'Save target'}</Button>
        {editing && <Button onClick={() => edit(null)}>{zh ? '取消编辑' : 'Cancel edit'}</Button>}</Space>
    </Form>}
  </Space>;
}
