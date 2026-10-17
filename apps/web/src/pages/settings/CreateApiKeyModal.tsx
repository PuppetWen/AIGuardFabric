import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Form, Input, InputNumber, Modal, Select, Typography, message } from 'antd';
import { settingsApi } from '@/api/settings';
import { api, useApiQuery } from '@/api/client';
import { AVAILABLE_SCOPES, validKeyScopes } from './keyScopes';

interface Props { open: boolean; onCancel: () => void; onConfirm: () => void; initialScopes?: string[] }
interface Values { name: string; scopes: string[]; days: number; agentId?: string }

/** Only the creation response contains the secret; never persist it in browser storage. */
export function CreateApiKeyModal({ open, onCancel, onConfirm, initialScopes = [] }: Props) {
  const { t, i18n } = useTranslation();
  const zh = i18n.language?.startsWith('zh') ?? false;
  const [form] = Form.useForm<Values>();
  const [createdKey, setCreatedKey] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [agentSearch, setAgentSearch] = useState('');
  const agents = useApiQuery('key-binding-agents', () => api.agents({ pageSize: 100, keyword: agentSearch }),
    { key: [agentSearch], enabled: open && !createdKey });

  async function submit() {
    if (createdKey) { onCancel(); return; }
    const values = await form.validateFields().catch(() => null);
    if (!values) return;
    setBusy(true);
    try {
      const result = await settingsApi.createKey({
        name: values.name.trim(), scopes: values.scopes, expires_in_secs: values.days * 86400,
        bound_agent_id: values.agentId,
      });
      setCreatedKey(result.data.plaintext);
      onConfirm();
    } catch (error) { message.error(error instanceof Error ? error.message : zh ? '创建失败' : 'Failed to create API key'); }
    finally { setBusy(false); }
  }

  return (
    <Modal open={open} title={t('settings.apiKeys.create')} onCancel={onCancel}
      onOk={() => void submit()} confirmLoading={busy} okText={createdKey ? (zh ? '已安全保存，关闭' : 'Saved, close') : (zh ? '创建' : 'Create')}
      maskClosable={!busy}>
      {createdKey ? <Alert type="success" showIcon message={t('settings.apiKeys.createdOnce')}
        description={<Typography.Paragraph copyable className="agf-mono"
          style={{ wordBreak: 'break-all' }}>{createdKey}</Typography.Paragraph>} /> :
        <Form form={form} layout="vertical" initialValues={{ scopes: validKeyScopes(initialScopes), days: 90 }}>
          <Alert type="info" showIcon message={zh
            ? '只授予当前用途需要的权限；创建后密钥明文只显示一次。'
            : 'Grant only the scopes needed for this client. The secret is shown only once.'} style={{ marginBottom: 16 }} />
          <Form.Item name="name" label={t('settings.apiKeys.column.name')}
            rules={[{ required: true, whitespace: true, max: 128 }]}>
            <Input placeholder={zh ? '例如：日志源接入' : 'For example: log source client'} maxLength={128} />
          </Form.Item>
          <Form.Item name="scopes" label={t('settings.apiKeys.column.scopes')} rules={[{ required: true }]}>
            <Select mode="multiple" options={AVAILABLE_SCOPES.map((value) => ({ value, label: value }))} />
          </Form.Item>
          <Form.Item name="days" label={zh ? '有效期（天）' : 'Expires after (days)'} rules={[{ required: true }]}>
            <InputNumber min={1} max={3650} precision={0} />
          </Form.Item>
          <Form.Item name="agentId" label={zh ? '绑定 Agent（可选）' : 'Bind to Agent (optional)'}
            extra={zh ? '绑定后，模型与 MCP 请求自动使用此 Agent 身份执行策略和配额，不接受冒用其他 Agent 的请求。'
              : 'Bound model and MCP requests use this Agent for policy and quota checks; callers cannot impersonate another Agent.'}>
            <Select showSearch allowClear filterOption={false} onSearch={setAgentSearch} loading={agents.isFetching}
              placeholder={zh ? '搜索本租户已登记的 Agent' : 'Search registered Agents in this tenant'}
              options={(agents.data?.data.items ?? []).map(agent => ({ value: agent.id, label: agent.name }))} />
          </Form.Item>
          {agents.error && <Alert type="warning" message={zh ? 'Agent 列表加载失败，请刷新后重试绑定。'
            : 'Could not load Agents. Refresh before binding this key.'} />}
        </Form>}
    </Modal>
  );
}
