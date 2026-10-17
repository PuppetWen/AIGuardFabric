import { useState } from 'react';
import { Button, Checkbox, Form, Input, Select, Space, Typography, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { callApi } from '@/api/transport';
import { useApiQuery } from '@/api/client';
import { useScopedOperation } from '@/components/useScopedOperation';

const SCAN_KINDS = [
  ['prompt', '提示词', 'Prompt'], ['log-payload', '日志载荷', 'Log payload'],
  ['document', '文档', 'Document'], ['tool-arguments', '工具参数', 'Tool arguments'],
  ['tool-result', '工具结果', 'Tool result'], ['mcp-request', 'MCP 请求', 'MCP request'],
  ['mcp-response', 'MCP 响应', 'MCP response'], ['model-output', '模型输出', 'Model output'],
  ['config', '配置', 'Configuration'], ['file-content', '文件内容', 'File content'],
  ['tool-definition', '工具定义', 'Tool definition'],
];
const DOMAINS = [
  ['prompt-attack', '提示词攻击', 'Prompt attacks'], ['credential-leak', '凭证泄露', 'Credential leaks'],
  ['rag-poison', 'RAG 投毒', 'RAG poisoning'], ['tool-abuse', '工具滥用', 'Tool abuse'],
  ['model-data', '模型与数据安全', 'Model and data security'],
];
interface Values { name: string; kind: string; text: string; assetId?: string; domains?: string[]; judge?: boolean; dataClass: string }

export function ScanForm({ canExecute, canReadAssets, canJudge, onSubmitted }: {
  canExecute: boolean; canReadAssets: boolean; canJudge: boolean; onSubmitted: (id: string) => void;
}) {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const [form] = Form.useForm<Values>();
  const [search, setSearch] = useState('');
  const operation = useScopedOperation();
  const assets = useApiQuery('scan-assets', () => callApi<{ items: { id: string; name: string }[] }>(
    '/api/v1/assets', () => null as never, { noFallback: true, query: { q: search, page_size: 50 } },
  ), { enabled: canReadAssets, key: [search] });
  const submit = (values: Values) => operation.run(async current => {
    if (!canExecute) return;
    try {
      const response = await callApi<{ taskId: string }>('/api/v1/scans', () => null as never, {
        noFallback: true, method: 'POST', body: {
          job_name: values.name, wait: false, use_llm_judge: values.judge === true,
          domains: values.domains ?? [], targets: [{
            label: values.name, kind: values.kind, text: values.text, asset_id: values.assetId, data_class: values.dataClass,
          }],
        },
      });
      if (!current()) return;
      form.setFieldValue('text', '');
      onSubmitted(response.data.taskId);
      void message.success(zh ? '扫描已受理，可在下方跟踪结果' : 'Scan accepted; track the result below');
    } catch (reason) {
      if (current()) void message.error(reason instanceof Error ? reason.message : String(reason));
    }
  });
  return <Form form={form} layout="vertical" initialValues={{ kind: 'prompt', domains: [], judge: false, dataClass: 'internal' }}
    disabled={!canExecute || operation.busy} onFinish={values => void submit(values)}>
    <Space align="start" wrap style={{ width: '100%' }}>
      <Form.Item name="name" label={zh ? '任务名称 / 目标标识' : 'Task name / target label'}
        rules={[{ required: true, whitespace: true }, { max: 200 }]}>
        <Input style={{ width: 270 }} maxLength={200} />
      </Form.Item>
      <Form.Item name="kind" label={zh ? '内容类型' : 'Content type'} rules={[{ required: true }]}>
        <Select style={{ width: 180 }} options={SCAN_KINDS.map(([value, cn, en]) => ({ value, label: zh ? cn : en }))} />
      </Form.Item>
      <Form.Item name="assetId" label={zh ? '关联资产（可选）' : 'Related asset (optional)'}>
        <Select showSearch allowClear filterOption={false} onSearch={setSearch} loading={assets.isLoading}
          disabled={!canExecute || !canReadAssets || operation.busy} style={{ width: 270 }}
          placeholder={zh ? '搜索当前组织的资产名称' : 'Search assets in this organization'}
          options={assets.data?.data.items.map(asset => ({ value: asset.id, label: asset.name + ' · ' + asset.id }))} />
      </Form.Item>
    </Space>
    <Form.Item name="dataClass" label={zh ? '数据分级（关联资产的更高分级仍生效）' : 'Data classification (higher asset classification still applies)'}>
      <Select options={['public', 'internal', 'confidential', 'restricted'].map(value => ({ value,
        label: zh ? ({ public: '公开', internal: '内部', confidential: '机密', restricted: '受限' }[value]) : value }))} />
    </Form.Item>
    {assets.error && <Typography.Text type="danger">{zh ? '资产列表加载失败，请稍后重新搜索' : 'Could not load assets; search again later'}</Typography.Text>}
    <Form.Item name="domains" label={zh ? '安全域（留空按内容类型选择）' : 'Security domains (automatic when empty)'}>
      <Select mode="multiple" allowClear options={DOMAINS.map(([value, cn, en]) => ({ value, label: zh ? cn : en }))} />
    </Form.Item>
    <Form.Item name="text" label={zh ? '待检测内容' : 'Content to inspect'} rules={[{ required: true }]}>
      <Input.TextArea rows={5} maxLength={1_048_576} autoComplete="off"
        placeholder={zh ? '粘贴提示词、日志、工具配置或文档内容。单项最多 1 MiB。' : 'Paste a prompt, log, tool configuration or document. Maximum 1 MiB.'} />
    </Form.Item>
    <Space wrap>
      <Form.Item name="judge" valuePropName="checked" noStyle>
        <Checkbox disabled={!canExecute || !canJudge || operation.busy}>{zh ? '启用模型二次研判（需模型调用权限）' : 'Request secondary model judgement (requires model call access)'}</Checkbox>
      </Form.Item>
      <Button htmlType="submit" type="primary" loading={operation.busy}>{zh ? '提交扫描' : 'Submit scan'}</Button>
      {!canExecute && <Typography.Text type="secondary">{zh ? '当前账号仅可查看任务' : 'This account can only view tasks'}</Typography.Text>}
    </Space>
  </Form>;
}
