import { useState } from 'react';
import { Alert, Button, Form, Input, Modal, Select, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { ApiRequestError, callApi } from '@/api/transport';
import type { AssetProfile } from '@/types/domain';

interface MetadataForm {
  name: string;
  owner: string;
  department: string;
  dataClass: string;
  reason: string;
}

export function AssetMetadataEditor({ profile, onSaved }: { profile: AssetProfile; onSaved: () => Promise<void> }) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const label = (cn: string, en: string) => zh ? cn : en;
  const [form] = Form.useForm<MetadataForm>();
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [expected, setExpected] = useState('');
  const governance = profile.governance;
  if (!governance?.canWrite) return null;
  const begin = () => {
    setExpected(governance.updatedAt);
    form.setFieldsValue({ name: profile.asset.name, owner: governance.owner ?? '',
      department: governance.department ?? '', dataClass: governance.dataClass, reason: '' });
    setError(''); setOpen(true);
  };
  const save = async (values: MetadataForm) => {
    setSaving(true); setError('');
    try {
      await callApi(`/api/v1/assets/${profile.asset.id}`, () => null, { method: 'PATCH', noFallback: true,
        body: { name: values.name.trim(), owner: values.owner.trim(), department: values.department.trim(),
          data_class: values.dataClass, expected_updated_at: expected, reason: values.reason.trim() } });
      setOpen(false);
      await onSaved();
    } catch (cause) {
      setError(cause instanceof ApiRequestError && cause.status === 409
        ? label('资产已被更新；请关闭表单、刷新详情后核对再保存。',
          'This asset changed. Close the form, reload its details and review before saving.')
        : cause instanceof Error ? cause.message : String(cause));
    } finally { setSaving(false); }
  };
  return <>
    <Button onClick={begin}>{label('更正资产资料', 'Edit asset details')}</Button>
    <Modal open={open} title={label('更正资产资料', 'Edit asset details')}
      onCancel={() => { if (!saving) setOpen(false); }} onOk={() => form.submit()}
      okText={label('保存更正', 'Save changes')} cancelText={label('取消', 'Cancel')}
      confirmLoading={saving} maskClosable={!saving}>
      <Typography.Paragraph type="secondary">{label(
        '这里只更正台账中的名称、归属和数据分级，不会修改外部 Agent 或端点。资产标识、指纹及生命周期须走各自专用流程。',
        'This corrects inventory name, ownership and data classification. It does not change an external Agent or endpoint. Identity and lifecycle have separate workflows.')}</Typography.Paragraph>
      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} />}
      <Form form={form} layout="vertical" disabled={saving} onFinish={values => void save(values)}>
        <Form.Item name="name" label={label('资产名称', 'Asset name')} rules={[{ required: true, whitespace: true }]}>
          <Input maxLength={256} /></Form.Item>
        <Form.Item name="owner" label={label('负责人', 'Owner')} rules={[{ required: true, whitespace: true }]}>
          <Input maxLength={256} /></Form.Item>
        <Form.Item name="department" label={label('部门（可留空）', 'Department (optional)')}>
          <Input maxLength={256} /></Form.Item>
        <Form.Item name="dataClass" label={label('数据分级', 'Data classification')}
          rules={[{ required: true }]}>
          <Select options={['public', 'internal', 'confidential', 'restricted'].map((value, index) => ({
            value, label: zh ? ['公开', '内部', '机密', '严格受限'][index] : value,
          }))} /></Form.Item>
        <Form.Item name="reason" label={label('更正原因（记入变更台账）', 'Reason (recorded in change history)')}
          rules={[{ required: true, whitespace: true }]}>
          <Input.TextArea rows={3} maxLength={1024} /></Form.Item>
      </Form>
    </Modal>
  </>;
}
