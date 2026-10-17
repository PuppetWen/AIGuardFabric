import { useState } from 'react';
import { Alert, Button, Form, Input, Popconfirm, Select, Space, Switch, Table, Typography, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { api, useApiQuery } from '@/api/client';
import { callApi } from '@/api/transport';
import { DataState } from '@/components/DataState';
import { useScopedOperation } from '@/components/useScopedOperation';
import { McpEndpointUsage } from '../mcp/McpEndpointUsage';

export interface McpTargetProfile {
  id: string; assetId: string; name: string; url: string; toolName: string; argumentName: string;
  detailToolName?: string | null; detailArgumentName?: string | null;
  enabled: boolean; version: number; credentialConfigured: boolean; canaryConfigured: boolean;
}
interface Values {
  name: string; assetId: string; url: string; toolName: string; argumentName: string;
  detailToolName?: string; detailArgumentName?: string;
  enabled: boolean; bearerToken?: string; protectedCanary?: string; clearToken?: boolean;
}

export function McpTargetsPanel({ canConfigure }: { canConfigure: boolean }) {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const [form] = Form.useForm<Values>();
  const [editing, setEditing] = useState<McpTargetProfile | null>(null);
  const [usageProfile, setUsageProfile] = useState<McpTargetProfile | null>(null);
  const [keyword, setKeyword] = useState('');
  const operation = useScopedOperation();
  const targets = useApiQuery('redteam-mcp-targets', () => callApi<{ items: McpTargetProfile[] }>(
    '/api/v1/redteam/mcp-targets', () => ({ items: [] }), { noFallback: true }), {});
  const assets = useApiQuery('redteam-mcp-assets', () => api.mcps({ page: 1, pageSize: 50, keyword }),
    { key: [keyword], enabled: canConfigure });
  const edit = (profile: McpTargetProfile | null) => {
    setEditing(profile);
    form.setFieldsValue(profile ? {
      name: profile.name, assetId: profile.assetId, url: profile.url, toolName: profile.toolName,
      argumentName: profile.argumentName, detailToolName: profile.detailToolName ?? '',
      detailArgumentName: profile.detailArgumentName ?? '',
      enabled: profile.enabled, bearerToken: '', protectedCanary: '',
      clearToken: false,
    } : { name: '', assetId: '', url: '', toolName: '', argumentName: 'query', detailToolName: '', detailArgumentName: '',
      enabled: true, bearerToken: '', protectedCanary: '', clearToken: false });
  };
  const save = (values: Values) => operation.run(async current => {
    try {
      await callApi('/api/v1/redteam/mcp-targets', () => null, { method: 'POST', noFallback: true, body: {
        id: editing?.id, expected_version: editing?.version ?? 0, asset_id: values.assetId,
        name: values.name, url: values.url, tool_name: values.toolName,
        argument_name: values.argumentName, enabled: values.enabled,
        detail_tool_name: values.detailToolName?.trim() || null,
        detail_argument_name: values.detailArgumentName?.trim() || null,
        ...(values.clearToken ? { bearer_token: '' } : values.bearerToken ? { bearer_token: values.bearerToken } : {}),
        ...(values.protectedCanary ? { protected_canary: values.protectedCanary } : {}),
      } });
      if (current()) { form.resetFields(); setEditing(null); await targets.refetch(); void message.success(zh ? 'MCP 目标已保存' : 'MCP target saved'); }
    } catch (error) { if (current()) void message.error(error instanceof Error ? error.message : String(error)); }
  });
  const remove = (profile: McpTargetProfile) => operation.run(async current => {
    try {
      await callApi(`/api/v1/redteam/mcp-targets/${encodeURIComponent(profile.id)}`, () => null,
        { method: 'DELETE', body: { expected_version: profile.version }, noFallback: true });
      if (current()) {
        if (editing?.id === profile.id) edit(null);
        if (usageProfile?.id === profile.id) setUsageProfile(null);
        await targets.refetch();
      }
    } catch (error) { if (current()) void message.error(error instanceof Error ? error.message : String(error)); }
  });
  return <Space direction="vertical" size="middle" style={{ width: '100%' }}>
    <Alert showIcon type="info" message={zh ? 'MCP 只读哨兵检测' : 'Read-only MCP canary probe'}
      description={zh
        ? '仅支持 2026-07-28 Streamable HTTP 的 JSON 响应。先在上游放置专用哨兵，配置已审计的只读查询工具；若要跨工具检测，再配置不同的只读详情工具。每次调用前核对 readOnlyHint 与单字符串参数。'
        : 'Supports JSON responses from 2026-07-28 Streamable HTTP. Place a protected canary upstream and configure an audited read-only query tool. For cross-tool probing, add a distinct read-only detail tool. Each call checks readOnlyHint and its string input.'} />
    <DataState loading={targets.isLoading} error={targets.error}>
      <Table rowKey="id" size="small" pagination={{ pageSize: 8 }} dataSource={targets.data?.data.items ?? []} columns={[
        { title: zh ? '目标' : 'Target', dataIndex: 'name' },
        { title: zh ? 'MCP 资产' : 'MCP asset', dataIndex: 'assetId', ellipsis: true },
        { title: zh ? '只读工具' : 'Read-only tool', dataIndex: 'toolName' },
        { title: zh ? '版本' : 'Version', dataIndex: 'version' },
        { title: zh ? '状态' : 'Status', render: (_, row: McpTargetProfile) => row.enabled ? (zh ? '启用' : 'Enabled') : (zh ? '停用' : 'Disabled') },
        { title: zh ? '操作' : 'Actions', render: (_, row: McpTargetProfile) => <Space>
          <Button size="small" onClick={() => setUsageProfile(row)}>{zh ? '用量' : 'Usage'}</Button>
          {canConfigure && <Button size="small" onClick={() => edit(row)}>{zh ? '编辑' : 'Edit'}</Button>}
          {canConfigure && <Popconfirm title={zh ? '删除这个目标配置？' : 'Delete target profile?'} onConfirm={() => void remove(row)}>
            <Button size="small" danger>{zh ? '删除' : 'Delete'}</Button>
          </Popconfirm>}
        </Space> },
      ]} />
    </DataState>
    {usageProfile && <Space direction="vertical" style={{ width: '100%' }}>
      <Space><Typography.Text strong>{usageProfile.name}</Typography.Text>
        <Button size="small" onClick={() => setUsageProfile(null)}>{zh ? '收起' : 'Close'}</Button></Space>
      <McpEndpointUsage id={usageProfile.id} redteamProfile zh={zh} />
    </Space>}
    {canConfigure && <Form<Values> form={form} layout="vertical" disabled={operation.busy} onFinish={values => void save(values)}
      initialValues={{ enabled: true, argumentName: 'query' }}>
      <Typography.Title level={5}>{editing ? (zh ? '编辑 MCP 目标' : 'Edit MCP target') : (zh ? '接入 MCP 目标' : 'Connect MCP target')}</Typography.Title>
      <Form.Item name="name" label={zh ? '配置名称' : 'Profile name'} rules={[{ required: true, whitespace: true }]}>
        <Input maxLength={160} />
      </Form.Item>
      <Input.Search placeholder={zh ? '搜索已纳管 MCP Server' : 'Search registered MCP servers'} onSearch={setKeyword} enterButton={zh ? '查找' : 'Search'} />
      <Form.Item name="assetId" label={zh ? 'MCP Server 资产' : 'MCP Server asset'} rules={[{ required: true }]}>
        <Select showSearch optionFilterProp="label" loading={assets.isLoading} options={(assets.data?.data.items ?? [])
          .map(asset => ({ value: asset.id, label: `${asset.name} (${asset.id})` }))}
          placeholder={zh ? '先在 MCP 管理页纳管' : 'Register the MCP server first'} />
      </Form.Item>
      <Form.Item name="url" label={zh ? 'Streamable HTTP 完整 URL' : 'Full Streamable HTTP URL'}
        rules={[{ required: true, type: 'url' }]}><Input maxLength={2048} /></Form.Item>
      <Form.Item name="toolName" label={zh ? '已审计只读工具名' : 'Audited read-only tool name'} rules={[{ required: true }]}>
        <Input maxLength={160} />
      </Form.Item>
      <Form.Item name="argumentName" label={zh ? '字符串查询参数名' : 'String query argument name'} rules={[{ required: true }]}>
        <Input maxLength={160} />
      </Form.Item>
      <Form.Item name="detailToolName" label={zh ? '只读详情工具名（跨工具用例可选）' : 'Read-only detail tool (optional for cross-tool case)'}
        extra={zh ? '必须与前一个工具不同；留空时无法执行 RT-MCP-003。' : 'Must differ from the first tool; RT-MCP-003 needs this.'}>
        <Input maxLength={160} />
      </Form.Item>
      <Form.Item name="detailArgumentName" label={zh ? '详情工具的字符串参数名（可选）' : 'Detail tool string argument (optional)'}>
        <Input maxLength={160} />
      </Form.Item>
      <Form.Item name="bearerToken" label={editing ? (zh ? '新令牌（留空保留）' : 'New token (blank keeps current)') : (zh ? 'Bearer 令牌（可选）' : 'Bearer token (optional)')}>
        <Input.Password autoComplete="off" maxLength={8192} />
      </Form.Item>
      {editing && <Form.Item name="clearToken" valuePropName="checked" label={zh ? '清除原令牌' : 'Clear existing token'}><Switch /></Form.Item>}
      <Form.Item name="protectedCanary" label={zh ? '受保护哨兵' : 'Protected canary'}
        extra={zh ? '16–128 位字母、数字、_ 或 -；必须已放入上游私有数据。' : '16–128 letters, digits, _ or -; it must already exist in upstream private data.'}
        rules={editing ? [] : [{ required: true }]}><Input autoComplete="off" maxLength={128} /></Form.Item>
      <Button onClick={() => form.setFieldValue('protectedCanary',
        Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join(''))}>
        {zh ? '生成哨兵' : 'Generate canary'}
      </Button>
      <Form.Item name="enabled" label={zh ? '允许执行' : 'Enabled'} valuePropName="checked"><Switch /></Form.Item>
      <Space><Button type="primary" htmlType="submit" loading={operation.busy}>{zh ? '保存配置' : 'Save target'}</Button>
        {editing && <Button onClick={() => edit(null)}>{zh ? '取消编辑' : 'Cancel edit'}</Button>}</Space>
    </Form>}
  </Space>;
}
