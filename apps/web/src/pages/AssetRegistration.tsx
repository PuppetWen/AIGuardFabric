import { newRequestId } from '@/utils/requestId';
import { useState } from 'react';
import { Alert, Button, Form, Input, Modal, Select, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { ApiRequestError, callApi } from '@/api/client';

type Application = {
  fingerprint: string; kind: string; name: string; owner: string; department: string;
  dataClass: string; endpoint: string; vendor: string; version: string; note: string;
  edrHostId?: string;
  scimUserId?: string;
};
const kinds = ['agent', 'mcp-server', 'mcp-client', 'skill', 'prompt-template', 'rag-kb', 'vector-store',
  'model-endpoint', 'credential', 'compute-node', 'ide-plugin', 'collector', 'data-source', 'other'];
const kindNames = ['Agent', 'MCP 服务', 'MCP 客户端', 'Skill / Tool / Function', '提示词模板', 'RAG 知识库', '向量库',
  '模型端点', '凭据条目', '算力节点', 'IDE 插件', '采集器', '数据源', '其他'];

export function AssetRegistration({ onSaved }: { onSaved: (id: string) => Promise<void> }) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [form] = Form.useForm<Application>();
  const selectedKind = Form.useWatch('kind', form);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [requestId, setRequestId] = useState('');
  const begin = () => {
    form.resetFields(); setRequestId(newRequestId()); setError(''); setOpen(true);
  };
  const save = async (values: Application) => {
    setBusy(true); setError('');
    try {
      const result = await callApi<{ asset: { id: string } }>('/api/v1/assets/register', () => ({ asset: { id: '' } }), {
        method: 'POST', noFallback: true,
        body: { ...values, dataClass: undefined, data_class: values.dataClass,
          edrHostId: undefined, edr_host_id: values.edrHostId ?? '',
          scimUserId: undefined, scim_user_id: values.scimUserId ?? '', request_id: requestId },
      });
      setOpen(false);
      await onSaved(result.data.asset.id);
    } catch (cause) {
      setError(cause instanceof ApiRequestError && cause.status === 409
        ? text('资产标识已存在。请关闭表单，搜索该标识并打开已有资产。', 'This inventory key exists. Close this form and search for the existing asset.')
        : cause instanceof Error ? cause.message : String(cause));
    } finally { setBusy(false); }
  };
  const required = [{ required: true, whitespace: true }];
  return <>
    <Button type="primary" onClick={begin}>{text('登记资产', 'Register asset')}</Button>
    <Modal open={open} title={text('登记资产申请', 'Register asset application')} confirmLoading={busy}
      onCancel={() => { if (!busy) setOpen(false); }} onOk={() => form.submit()} maskClosable={!busy}
      okText={text('提交申请', 'Submit application')} cancelText={text('取消', 'Cancel')}>
      <Typography.Paragraph>{text('登记后进入“申请中”，从详情进行评审。此处维护台账；模型调用、MCP 连接和凭据请在对应接入页面配置。',
        'Registration starts in Requested. Review it from the detail. Configure model calls, MCP connections and credentials in their onboarding pages.')}</Typography.Paragraph>
      {error && <Alert type="error" showIcon message={error} description={text('输入已保留。网络失败时可原样重试，避免重复登记。',
        'Your input is retained. Retry unchanged after a network failure to avoid duplicate registration.')} />}
      <Form name="asset-registration" form={form} layout="vertical" disabled={busy} onFinish={values => void save(values)}
        initialValues={{ kind: 'agent', dataClass: 'internal', department: '', endpoint: '', vendor: '', version: '' }}>
        <Form.Item name="name" label={text('资产名称', 'Asset name')} rules={required}><Input maxLength={80} /></Form.Item>
        <Form.Item name="kind" label={text('资产类型', 'Asset kind')} rules={required}>
          <Select options={kinds.map((value, index) => ({ value, label: zh ? kindNames[index] : value }))} /></Form.Item>
        <Form.Item name="fingerprint" label={text('唯一资产标识', 'Unique inventory key')} rules={required}
          extra={text('例如 finance/reporting-mcp；与采集器的 fingerprint 一致时自动归并。不要填写密码。',
            'For example finance/reporting-mcp. Discovery merges by this fingerprint. Do not enter a password.')}><Input maxLength={80} /></Form.Item>
        <Form.Item name="owner" label={text('负责人', 'Owner')} rules={required}><Input maxLength={80} /></Form.Item>
        <Form.Item name="department" label={text('部门', 'Department')}><Input maxLength={80} /></Form.Item>
        <Form.Item name="dataClass" label={text('数据分级', 'Data classification')} rules={required}>
          <Select options={['public', 'internal', 'confidential', 'restricted'].map((value, index) => ({ value,
            label: zh ? ['公开', '内部', '机密', '严格受限'][index] : value }))} /></Form.Item>
        <Form.Item name="endpoint" label={text('端点（可选）', 'Endpoint (optional)')}
          extra={text('完整 URL 或 stdio:名称；不包含密钥、查询参数和命令参数。', 'Absolute URL or stdio:name; omit secrets, query strings and command arguments.')}>
          <Input maxLength={600} /></Form.Item>
        <Form.Item name="vendor" label={text('厂商', 'Vendor')}><Input maxLength={80} /></Form.Item>
        <Form.Item name="version" label={text('版本', 'Version')}><Input maxLength={40} /></Form.Item>
        <Form.Item name="edrHostId" label={text('EDR 主机编号（可选）', 'EDR host ID (optional)')}
          extra={text('从 EDR 控制台复制。案件通过 EDR 隔离时，填写的主机编号必须与此处一致。',
            'Copy from the EDR console. Case isolation must use this exact host ID.')}>
          <Input maxLength={128} /></Form.Item>
        {selectedKind === 'credential' && <Form.Item name="scimUserId" label={text('SCIM 用户编号（可选）', 'SCIM user ID (optional)')}
          extra={text('从身份平台的 SCIM 用户资源复制 ID；案件身份停用只能使用此编号。',
            'Copy the SCIM User resource ID from the identity provider; case deactivation uses this exact ID.')}
          rules={[{ pattern: /^(?!\.\.?$)[A-Za-z0-9_.-]*$/ }]}><Input maxLength={128} /></Form.Item>}
        <Form.Item name="note" label={text('申请用途', 'Application purpose')} rules={required}><Input.TextArea rows={2} maxLength={600} /></Form.Item>
      </Form>
    </Modal>
  </>;
}
