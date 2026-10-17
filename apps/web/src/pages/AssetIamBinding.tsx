import { useState } from 'react';
import { Alert, Button, Form, Input, Modal, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { ApiRequestError, callApi } from '@/api/transport';
import type { AssetProfile } from '@/types/domain';

type Binding = { userId: string; reason: string };

export function AssetIamBinding({ profile, onSaved }: { profile: AssetProfile; onSaved: () => Promise<void> }) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [form] = Form.useForm<Binding>();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const governance = profile.governance;
  const current = profile.asset.scimUserId ?? '';
  if (profile.asset.kind !== 'credential') return null;
  const begin = () => { form.setFieldsValue({ userId: current, reason: '' }); setError(''); setOpen(true); };
  const save = async (values: Binding) => {
    if (!governance) return;
    setBusy(true); setError('');
    try {
      await callApi(`/api/v1/assets/${profile.asset.id}/scim-user`, () => null, {
        method: 'PUT', noFallback: true,
        body: { user_id: values.userId.trim(), expected_updated_at: governance.updatedAt,
          reason: values.reason.trim() },
      });
      setOpen(false); await onSaved();
    } catch (cause) {
      setError(cause instanceof ApiRequestError && cause.status === 409
        ? text('资产已更新。关闭窗口并刷新详情，再核对 SCIM 用户编号。',
          'The asset changed. Close this dialog, reload details and verify the SCIM user ID.')
        : cause instanceof Error ? cause.message : String(cause));
    } finally { setBusy(false); }
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Text>{text('SCIM 用户编号：', 'SCIM user ID: ')}
      {current ? <Typography.Text copyable>{current}</Typography.Text> : text('尚未绑定', 'Not bound')}</Typography.Text>
    {governance?.canWrite && <Button onClick={begin}>{text('绑定或修改 SCIM 用户', 'Bind or change SCIM user')}</Button>}
    <Typography.Text type="secondary">{text('仅凭据类资产可绑定。请从身份平台复制资源 ID，案件停用只作用于此编号。',
      'Only credential assets can be bound. Copy the resource ID from your identity provider; the case action targets only this ID.')}</Typography.Text>
    <Modal open={open} title={text('SCIM 用户绑定', 'SCIM user binding')} confirmLoading={busy}
      onCancel={() => !busy && setOpen(false)} onOk={() => form.submit()} maskClosable={!busy}>
      {error && <Alert type="error" showIcon message={error} />}
      <Form form={form} layout="vertical" onFinish={values => void save(values)} disabled={busy}>
        <Form.Item name="userId" label={text('远端 SCIM 用户编号', 'Remote SCIM user ID')}
          extra={text('留空并保存会解除绑定，随后案件不能停用该身份。',
            'Save an empty value to remove the binding and prevent case deactivation.')}
          rules={[{ pattern: /^(?!\.\.?$)[A-Za-z0-9_.-]*$/, message: text('只允许字母、数字、点、横线和下划线',
            'Use only letters, digits, dots, hyphens and underscores') }]}><Input maxLength={128} /></Form.Item>
        <Form.Item name="reason" label={text('变更原因', 'Reason for change')}
          rules={[{ required: true, whitespace: true, max: 1024 }]}><Input.TextArea rows={2} /></Form.Item>
      </Form>
    </Modal>
  </Space>;
}
