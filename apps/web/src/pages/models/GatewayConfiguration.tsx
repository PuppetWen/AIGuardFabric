import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Drawer, Form, Input, Select, Space, Switch, Table, Tag, Typography, message, Popconfirm } from 'antd';
import { Link } from 'react-router-dom';
import { useApiQuery } from '@/api/client';
import { gatewayApi, type GatewayEndpoint, type EndpointInput } from '@/api/gateway';
import { ApiRequestError } from '@/api/transport';
import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import { GatewayPricingFields } from './GatewayPricingFields';

type EndpointFormValues = Omit<EndpointInput, 'pricing' | 'expected_version'> & {
  inputPriceCny: number; outputPriceCny: number; cachedPriceCny: number;
};

const providers = ['mock', 'openai', 'anthropic', 'gemini', 'azure-openai', 'bedrock', 'dashscope',
  'ark', 'hunyuan', 'qianfan', 'moonshot', 'deepseek', 'zhipu', 'minimax', 'ollama', 'vllm', 'custom-openai-compat'];
const defaults: EndpointFormValues = { name: '', provider: 'mock', model: 'agf-mock',
  base_url: 'http://mock.invalid/v1', local_deployment: true, max_data_class: 'internal', enabled: true,
  inputPriceCny: 0, outputPriceCny: 0, cachedPriceCny: 0 };

/** 配置和试调用使用同一套网关，失败时保留表单，密钥不回填。 */
export function GatewayConfiguration({ canWrite }: { canWrite: boolean }) {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const endpoints = useApiQuery('gateway-configuration', gatewayApi.list);
  const catalog = useApiQuery('gateway-providers', gatewayApi.providers);
  const [form] = Form.useForm<EndpointFormValues>();
  const provider = Form.useWatch('provider', form);
  const [editing, setEditing] = useState<GatewayEndpoint>();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [errorText, setErrorText] = useState('');
  const [conflict, setConflict] = useState(false);
  const [testing, setTesting] = useState<string>();
  const [reply, setReply] = useState<string>();

  const edit = (row?: GatewayEndpoint) => {
    setErrorText('');
    setConflict(false);
    setEditing(row);
    form.resetFields();
    form.setFieldsValue(row ? { name: row.name, provider: row.provider, model: row.model,
      base_url: row.baseUrl, local_deployment: row.localDeployment, max_data_class: row.maxDataClass,
      enabled: row.enabled, api_version: row.apiVersion,
      inputPriceCny: row.pricing.promptMicroPer1k / 1000000,
      outputPriceCny: row.pricing.completionMicroPer1k / 1000000,
      cachedPriceCny: row.pricing.cachedPromptMicroPer1k / 1000000 } : defaults);
    setOpen(true);
  };
  const chooseProvider = (value: string) => {
    if (editing?.provider === value) {
      form.setFieldsValue({ base_url: editing.baseUrl, model: editing.model,
        api_key: undefined, local_deployment: editing.localDeployment });
      return;
    }
    const entries = catalog.data?.data.items ?? [];
    const selected = entries.find(item => item.value === value);
    const currentUrl = String(form.getFieldValue('base_url') ?? '');
    const isSuggested = currentUrl === defaults.base_url || currentUrl === editing?.baseUrl ||
      entries.some(item => item.suggestedBaseUrl === currentUrl);
    if (!currentUrl || isSuggested) {
      form.setFieldValue('base_url', selected && !selected.requiresCustomBaseUrl ? selected.suggestedBaseUrl : '');
    }
    form.setFieldsValue({ model: '', api_key: undefined });
    if (selected) form.setFieldValue('local_deployment', selected.localDeployment);
  };
  const save = async () => {
    if (!canWrite || busy || conflict) return;
    setBusy(true);
    setErrorText('');
    try {
      const { inputPriceCny, outputPriceCny, cachedPriceCny, ...values } = await form.validateFields();
      await gatewayApi.save(editing?.id, { ...values, expected_version: editing?.version ?? 0, pricing: {
        prompt_micro_per_1k: Math.round(inputPriceCny * 1000000),
        completion_micro_per_1k: Math.round(outputPriceCny * 1000000),
        cached_prompt_micro_per_1k: Math.round(cachedPriceCny * 1000000),
      } });
      message.success(text("端点已保存，下一次调用生效", "Endpoint saved; the next call uses this configuration"));
      setOpen(false);
      await endpoints.refetch();
    } catch (error) {
      setConflict(error instanceof ApiRequestError && error.status === 409);
      if (error instanceof Error) setErrorText(error.message);
    } finally { setBusy(false); }
  };
  const loadLatest = async () => {
    if (!editing || busy) return;
    setBusy(true);
    try {
      const result = await gatewayApi.list();
      const current = result.data.items.find(item => item.id === editing.id);
      if (!current) { setOpen(false); await endpoints.refetch(); return; }
      edit(current);
      await endpoints.refetch();
    } catch (error) { if (error instanceof Error) setErrorText(error.message); }
    finally { setBusy(false); }
  };
  const test = async (row: GatewayEndpoint) => {
    if (!canWrite || testing) return;
    setTesting(row.id);
    setReply(undefined);
    try {
      const result = await gatewayApi.test(row.id);
      setReply(`${row.mocked ? text("模拟回复", "Mock reply") : text("上游回复", "Upstream reply")}：${result.data.choices[0]?.message.content ?? ''}`);
    } catch (error) { message.error(error instanceof Error ? error.message : text("调用失败", "Call failed")); }
    finally { setTesting(undefined); }
  };
  return <Panel title={text("模型接入配置", "Gateway configuration")} extra={<Button disabled={!canWrite} type="primary" onClick={() => edit()}>{text("添加端点", "Add endpoint")}</Button>}>
    <Alert type="info" showIcon style={{ marginBottom: 12 }} message={text("先添加端点，再创建具有 models:read、models:write 权限的 API Key", "Configure an endpoint, then create an API key scoped to models:read and models:write")}
      description={<span>{text("OpenAI 客户端 Base URL：", "OpenAI client Base URL: ")}<Typography.Text code copyable>{`${window.location.origin}/v1`}</Typography.Text>。
        {text(" Claude Code 原生 Messages 使用平台根地址：", " Claude Code native Messages uses the platform root: ")}
        <Typography.Text code copyable>{window.location.origin}</Typography.Text>。
        {text("全局模拟模式开启时不会调用外部模型；试调用真实端点会消耗厂商额度。",
          "Global mock mode does not call external models. Real test calls consume provider quota. ")}
        <Link to="/guide?tab=platforms">{text("查看接入指南", "View connection guide")}</Link></span>} />
    <DataState loading={endpoints.isLoading} error={endpoints.error}>
      <Table<GatewayEndpoint> rowKey="id" size="small" dataSource={endpoints.data?.data.items ?? []} scroll={{ x: 900 }}
        columns={[
          { title: text("名称", "Name"), dataIndex: 'name' },
          { title: text("厂商 / 模型", "Provider / model"), render: (_, row) => `${row.provider} / ${row.model}` },
          { title: 'Base URL', dataIndex: 'baseUrl', ellipsis: true },
          { title: text("状态", "Status"), render: (_, row) => <Space><Tag color={row.enabled ? 'green' : 'default'}>{row.enabled ? text("启用", "Enabled") : text("停用", "Disabled")}</Tag>
            <Tag color={row.mocked ? 'orange' : 'blue'}>{row.mocked ? text("模拟", "Mock") : text("真实调用", "Real calls")}</Tag></Space> },
          { title: text("操作", "Actions"), render: (_, row) => <Space>
            <Button disabled={!canWrite} size="small" onClick={() => edit(row)}>{text("编辑", "Edit")}</Button>
            <Button size="small" disabled={!canWrite || !row.enabled || Boolean(testing)} loading={testing === row.id} onClick={() => void test(row)}>{text("试调用", "Test call")}</Button>
            <Popconfirm title={text("删除此端点？使用它的客户端将无法继续调用。", "Delete this endpoint? Clients using it will no longer be able to call it.")} onConfirm={async () => {
              if (!canWrite) return;
              try { await gatewayApi.remove(row.id, row.version); await endpoints.refetch(); }
              catch (error) { message.error(error instanceof Error ? error.message : text("删除失败", "Delete failed")); await endpoints.refetch(); }
            }}><Button disabled={!canWrite} danger size="small">{text("删除", "Delete")}</Button></Popconfirm>
          </Space> },
        ]} />
    </DataState>
    {reply && <Alert type="success" message={reply} style={{ marginTop: 12 }} />}
    <Drawer title={editing ? text("编辑模型端点", "Edit model endpoint") : text("添加模型端点", "Add model endpoint")} open={open} onClose={() => { if (!busy) setOpen(false); }} width={520}
      extra={<Button disabled={!canWrite || conflict} type="primary" loading={busy} onClick={() => void save()}>{text("保存", "Save")}</Button>}>
      <Form name="model-endpoint" disabled={!canWrite || busy} form={form} layout="vertical" initialValues={defaults}>
        {catalog.error && <Alert type="warning" showIcon style={{ marginBottom: 16 }}
          message={text('厂商地址建议暂时不可用，请手动填写 Base URL。',
            'Provider URL suggestions are unavailable. Enter the Base URL manually.')} />}
        {errorText && <Alert type="error" showIcon message={errorText} style={{ marginBottom: 16 }}
          description={text('草稿已保留，修正后可再次保存。', 'Your draft is retained. Correct it and save again.')} />}
        {conflict && <Popconfirm title={text('丢弃当前草稿并加载最新版本？', 'Discard this draft and load the latest version?')}
          onConfirm={() => void loadLatest()}><Button disabled={busy} style={{ marginBottom: 12 }}>
            {text('加载最新版本', 'Load latest version')}</Button></Popconfirm>}
        <Form.Item name="name" label={text("名称", "Name")} rules={[{ required: true }]}><Input maxLength={128} /></Form.Item>
        <Form.Item name="provider" label={text("厂商协议", "Provider protocol")} rules={[{ required: true }]}>
          <Select disabled={catalog.isLoading} loading={catalog.isLoading}
            options={(catalog.data?.data.items.map(item => item.value) ?? providers).map(value => ({ value }))}
            onChange={chooseProvider} />
        </Form.Item>
        <Form.Item name="model" label={text("厂商模型 ID", "Provider model ID")} rules={[{ required: true }]}><Input placeholder={text("填写厂商控制台的模型或部署名称", "Enter the model or deployment name from the provider console")} /></Form.Item>
        <Form.Item name="base_url" label={text("厂商 Base URL", "Provider Base URL")} rules={[{ required: true }, { type: 'url' }]}
          extra={<span>{text("厂商建议地址会在选择协议后填入；Azure、Bedrock 和本地模型须填写自己的资源或可达地址。手动填写的 URL 不会被切换厂商覆盖。", "A provider suggestion is filled after selection. Enter your own resource or reachable address for Azure, Bedrock and local models. Switching providers preserves a URL you entered yourself.")}
            {provider && catalog.data?.data.items.find(item => item.value === provider)?.requiresCustomBaseUrl &&
              <Typography.Text code style={{ marginLeft: 6 }}>{catalog.data.data.items.find(item => item.value === provider)?.suggestedBaseUrl}</Typography.Text>}
          </span>}>
          <Input /></Form.Item>
        {provider === 'azure-openai' && <Form.Item name="api_version" label={text("Azure API 版本（旧版部署地址）", "Azure API version (legacy deployment address)")}
          extra={text("推荐 Base URL 为 https://资源名.openai.azure.com/openai/v1。旧版 /openai/deployments/部署名 默认使用 2024-10-21；可在这里覆盖。URL 已含 api-version 时以 URL 为准。", "Use https://RESOURCE.openai.azure.com/openai/v1. Legacy /openai/deployments/DEPLOYMENT defaults to 2024-10-21. A version already in the URL takes precedence.")}>
          <Input placeholder="2024-10-21" maxLength={64} /></Form.Item>}
        <Form.Item name="api_key" label={text("厂商凭据", "Provider credential")} extra={text("可留空；加密保存，不回显。已有凭据时，编辑留空保留原值，更换厂商或地址须重新填写。Bedrock 填写包含 access_key_id、secret_access_key、可选 session_token 的 JSON。", "Optional; encrypted and never displayed again. If a credential is already saved, leaving this blank retains it; changing provider or URL requires a replacement. For Bedrock, enter JSON with access_key_id, secret_access_key and optional session_token.")}>
          <Input.Password autoComplete="new-password" /></Form.Item>
        <Alert type="info" showIcon style={{ marginBottom: 16 }} message={text("未保存上游凭据的端点使用本地 Mock，零上游外发", "Endpoints without saved upstream credentials use local Mock, with zero upstream requests")}
          description={text("受控内网的 Ollama/vLLM 是例外：即使没有凭据，仍会真实请求配置的本地服务。显式填写的无效凭据会报错，不会自动转为 Mock。", "Controlled private-network Ollama/vLLM deployments are an exception: they still send real requests to the configured local service without a credential. Explicit invalid credentials are rejected and do not silently select Mock.")} />
        <Form.Item name="local_deployment" label={text("端点在受控内网", "Endpoint is in a controlled private network")}
          extra={text("只有确认服务地址位于受控内网时才开启。Ollama/vLLM 在 Docker 中不能用工作站的 127.0.0.1，请填写容器可达的内网地址。",
            "Enable only after verifying the endpoint is in a controlled private network. From Docker, 127.0.0.1 is the container itself; enter an address reachable by the container for Ollama/vLLM.")}
          valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name="max_data_class" label={text("允许的最高数据分级", "Maximum allowed data classification")}><Select options={[
          { value: 'public', label: text("公开", "Public") }, { value: 'internal', label: text("内部", "Internal") },
          { value: 'confidential', label: text("机密", "Confidential") }, { value: 'restricted', label: text("严格限制（仅受控内网）", "Restricted (controlled private network only)") },
        ]} /></Form.Item>
        <GatewayPricingFields />
        <Form.Item name="enabled" label={text("启用", "Enabled")} valuePropName="checked"><Switch /></Form.Item>
      </Form>
    </Drawer>
  </Panel>;
}
