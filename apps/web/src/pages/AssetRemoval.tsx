import { useState } from 'react';
import { Alert, Button, Form, Input, Modal, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { ApiRequestError, callApi } from '@/api/transport';
import type { AssetProfile } from '@/types/domain';

interface RemovalForm { confirmName: string; reason: string }

export function AssetRemoval({ profile, onRemoved }: { profile: AssetProfile; onRemoved: () => Promise<void> }) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [form] = Form.useForm<RemovalForm>();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [expected, setExpected] = useState('');
  const governance = profile.governance;
  if (!governance?.canWrite || !['archived', 'rejected'].includes(governance.lifecycle)) return null;
  const begin = () => {
    setExpected(governance.updatedAt);
    form.resetFields();
    setError('');
    setOpen(true);
  };
  const remove = async (values: RemovalForm) => {
    setBusy(true); setError('');
    try {
      await callApi(`/api/v1/assets/${profile.asset.id}`, () => null, { method: 'DELETE', noFallback: true,
        body: { expected_updated_at: expected, confirm_name: values.confirmName, reason: values.reason.trim() } });
      setOpen(false);
      await onRemoved();
    } catch (cause) {
      setError(cause instanceof ApiRequestError && cause.status === 409
        ? text('资产已变化；请关闭窗口，刷新详情并核对后重试。',
          'The asset changed. Close this dialog, refresh its details and review before trying again.')
        : cause instanceof Error ? cause.message : String(cause));
    } finally { setBusy(false); }
  };
  return <>
    <Button danger onClick={begin}>{text('从当前台账移除', 'Remove from current inventory')}</Button>
    <Modal open={open} title={text('从当前台账移除资产', 'Remove asset from current inventory')}
      onCancel={() => { if (!busy) setOpen(false); }} onOk={() => form.submit()}
      okText={text('确认移除', 'Confirm removal')} okButtonProps={{ danger: true }}
      cancelText={text('取消', 'Cancel')} confirmLoading={busy} maskClosable={!busy}>
      <Typography.Paragraph type="secondary">{text(
        '仅从当前台账隐藏该资产；变更证据和审计记录保留。若采集源仍上报相同指纹，资产会重新出现。此操作不会停用外部服务或撤销凭据。',
        'This hides the asset from current inventory while retaining change evidence and audit history. It reappears if a source reports the same fingerprint. External services and credentials remain active.')}</Typography.Paragraph>
      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} />}
      <Form form={form} layout="vertical" disabled={busy} onFinish={values => void remove(values)}>
        <Form.Item name="confirmName" label={text('输入资产名称以确认', 'Type the asset name to confirm')}
          rules={[{ required: true }, { validator: async (_, value: string) => {
            if (value !== profile.asset.name) throw new Error(text('名称与当前资产不一致', 'Name does not match this asset'));
          } }]}>
          <Input maxLength={256} autoComplete="off" /></Form.Item>
        <Form.Item name="reason" label={text('移除原因（记入审计）', 'Reason (recorded in audit)')}
          rules={[{ required: true, whitespace: true }]}>
          <Input.TextArea rows={3} maxLength={1024} /></Form.Item>
      </Form>
    </Modal>
  </>;
}
