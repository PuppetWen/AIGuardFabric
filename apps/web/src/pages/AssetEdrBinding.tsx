import { useState } from 'react';
import { Alert, Button, Form, Input, Modal, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { ApiRequestError, callApi } from '@/api/transport';
import type { AssetProfile } from '@/types/domain';

type Binding = { hostId: string; reason: string };

export function AssetEdrBinding({ profile, onSaved }: { profile: AssetProfile; onSaved: () => Promise<void> }) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [form] = Form.useForm<Binding>();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const governance = profile.governance;
  const current = profile.asset.edrHostId ?? '';
  const begin = () => {
    form.setFieldsValue({ hostId: current, reason: '' });
    setError(''); setOpen(true);
  };
  const save = async (values: Binding) => {
    if (!governance) return;
    setBusy(true); setError('');
    try {
      await callApi(`/api/v1/assets/${profile.asset.id}/edr-host`, () => null, {
        method: 'PUT', noFallback: true,
        body: { host_id: values.hostId.trim(), expected_updated_at: governance.updatedAt,
          reason: values.reason.trim() },
      });
      setOpen(false);
      await onSaved();
    } catch (cause) {
      setError(cause instanceof ApiRequestError && cause.status === 409
        ? text('资产已被别人修改。请关闭窗口刷新详情，再核对主机编号。',
          'The asset changed. Close this dialog, reload its details, and verify the host ID.')
        : cause instanceof Error ? cause.message : String(cause));
    } finally { setBusy(false); }
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Text>{text('EDR 主机编号：', 'EDR host ID: ')}
      {current ? <Typography.Text copyable>{current}</Typography.Text> : text('尚未绑定', 'Not bound')}</Typography.Text>
    {governance?.canWrite && <Button onClick={begin}>{text('绑定或修改 EDR 主机', 'Bind or change EDR host')}</Button>}
    <Typography.Text type="secondary">{text('案件隔离只能操作与资产绑定的编号。先从 EDR 控制台核对主机，再保存绑定。',
      'Case isolation can target only the host bound to this asset. Verify the ID in EDR before saving.')}</Typography.Text>
    <Modal open={open} title={text('EDR 主机绑定', 'EDR host binding')} confirmLoading={busy}
      onCancel={() => !busy && setOpen(false)} onOk={() => form.submit()} maskClosable={!busy}>
      {error && <Alert type="error" showIcon message={error} />}
      <Form form={form} layout="vertical" onFinish={values => void save(values)} disabled={busy}>
        <Form.Item name="hostId" label={text('远端主机编号', 'Remote host ID')}
          extra={text('留空并保存会解除绑定，随后不能从案件隔离此资产。',
            'Save an empty value to remove the binding and prevent future case isolation.')}
          rules={[{ pattern: /^(?!\.\.?$)[A-Za-z0-9_.-]*$/, message: text('只允许字母、数字、点、横线和下划线',
            'Use only letters, digits, dots, hyphens and underscores') }]}>
          <Input maxLength={128} /></Form.Item>
        <Form.Item name="reason" label={text('变更原因', 'Reason for change')}
          rules={[{ required: true, whitespace: true, max: 1024 }]}><Input.TextArea rows={2} /></Form.Item>
      </Form>
    </Modal>
  </Space>;
}
