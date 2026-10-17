import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Form, Input, Modal, Popconfirm, Space, Table, Tag, message } from 'antd';
import { ApiRequestError, callApi } from '@/api/transport';
import type { Tenant } from '@/types/domain';

export function TenantDirectory({ tenants, reload }: { tenants: Tenant[]; reload: () => void }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [form] = Form.useForm<{ slug: string; name: string }>();
  const save = async () => {
    const values = await form.validateFields();
    setBusy(true);
    try {
      await callApi('/api/v1/tenants', () => null, { method: 'POST', body: values });
      message.success(t('settings.directory.created'));
      setOpen(false); form.resetFields(); reload();
    } catch (error) { message.error(String(error)); }
    finally { setBusy(false); }
  };
  const toggle = async (tenant: Tenant) => {
    if (!tenant.directoryVersion) {
      message.error(t('settings.directory.conflict'));
      reload();
      return;
    }
    setBusy(true);
    try {
      await callApi(`/api/v1/tenants/${tenant.id}`, () => null, {
        method: 'PATCH', body: { name: tenant.directoryName ?? tenant.name, enabled: tenant.enabled === false,
          expected_version: tenant.directoryVersion },
      });
      reload(); message.success(t('settings.directory.statusUpdated'));
    } catch (error) {
      if (error instanceof ApiRequestError && error.status === 409) {
        reload(); message.error(t('settings.directory.conflict'));
      } else { message.error(String(error)); }
    }
    finally { setBusy(false); }
  };
  return <Space direction="vertical" style={{ width: '100%' }} size="middle">
    <Alert type="info" showIcon message={t('settings.directory.intro')}
      description={t('settings.directory.steps')} />
    <Button type="primary" onClick={() => setOpen(true)}>{t('settings.directory.create')}</Button>
    <Table rowKey="id" dataSource={tenants} loading={busy} columns={[
      { title: t('settings.directory.name'), render: (_, row) => row.directoryName ?? row.name },
      { title: t('settings.directory.slug'), dataIndex: 'slug' },
      { title: t('settings.directory.status'), render: (_, row) => <Tag color={row.enabled === false ? 'default' : 'green'}>
        {t(row.enabled === false ? 'settings.directory.disabled' : 'settings.directory.enabled')}</Tag> },
      { title: t('settings.directory.action'), render: (_, row) => <Popconfirm
        title={t(row.enabled === false ? 'settings.directory.confirmEnable' : 'settings.directory.confirmDisable')}
        onConfirm={() => toggle(row)}>
        <Button disabled={row.id === '00000000-0000-0000-0000-000000000001'}>
          {t(row.enabled === false ? 'settings.directory.enable' : 'settings.directory.disable')}</Button>
      </Popconfirm> },
    ]} />
    <Modal title={t('settings.directory.create')} open={open} onCancel={() => setOpen(false)} onOk={() => void save()} confirmLoading={busy}>
      <Form form={form} layout="vertical">
        <Form.Item name="name" label={t('settings.directory.organization')} rules={[{ required: true, max: 128 }]}><Input /></Form.Item>
        <Form.Item name="slug" label={t('settings.directory.slug')} extra={t('settings.directory.slugHelp')}
          rules={[{ required: true, pattern: /^[a-z0-9-]{2,64}$/, message: t('settings.directory.slugRule') }]}>
          <Input placeholder={t('settings.directory.slugExample')} /></Form.Item>
      </Form>
    </Modal>
  </Space>;
}
