import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Form, Input, Modal, Select, message } from 'antd';
import { settingsApi, type NewUser } from '@/api/settings';
import { userRoleKey } from '@/utils/labels';
import { ROLES } from './settings.data';

interface Props { open: boolean; onCancel: () => void; onConfirm: () => void }

/** Create a real tenant account; its initial password must be changed on first login. */
export function AddUserModal({ open, onCancel, onConfirm }: Props) {
  const { t } = useTranslation();
  const [form] = Form.useForm<NewUser>();
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (open) form.resetFields(); }, [open, form]);

  async function submit() {
    const values = await form.validateFields().catch(() => null);
    if (!values) return;
    setBusy(true);
    try {
      await settingsApi.createUser(values);
      form.resetFields();
      onConfirm();
    } catch (error) { message.error(error instanceof Error ? error.message : '创建失败'); }
    finally { setBusy(false); }
  }

  return (
    <Modal open={open} title={t('settings.users.add')} onCancel={onCancel}
      onOk={() => void submit()} confirmLoading={busy} maskClosable={!busy}>
      <Alert type="info" showIcon message="创建后可用用户名和初始密码登录；首次登录必须改密。"
        description="请通过可信渠道将初始密码交给使用者。" style={{ marginBottom: 16 }} />
      <Form form={form} layout="vertical" initialValues={{ role: 'viewer', display_name: '' }}>
        <Form.Item name="username" label={t('settings.users.column.username')}
          rules={[{ required: true, whitespace: true, max: 80 }]}><Input autoComplete="off" /></Form.Item>
        <Form.Item name="display_name" label={t('settings.users.column.displayName')}><Input /></Form.Item>
        <Form.Item name="email" label={t('settings.users.column.email')}
          rules={[{ required: true }, { type: 'email' }]}><Input type="email" /></Form.Item>
        <Form.Item name="password" label="初始密码"
          rules={[{ required: true, min: 12 }]} extra="至少 12 位，包含大小写字母、数字、符号中的至少三类。">
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        <Form.Item name="role" label={t('settings.users.column.role')} rules={[{ required: true }]}>
          <Select options={ROLES.filter((role) => role !== 'owner')
            .map((role) => ({ value: role, label: t(userRoleKey(role)) }))} />
        </Form.Item>
      </Form>
    </Modal>
  );
}
