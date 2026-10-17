import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Card, Form, Input, QRCode, Space, Typography, message } from 'antd';
import { useApiQuery } from '@/api/client';
import { callApi } from '@/api/transport';
import { DataState, PageHeader } from '@/components/DataState';
import { logoutSession } from '@/api/session';

/** 绑定用途会话可访问此页，平台其它操作由后端拒绝。敏感信息仅保留在页面内存。 */
export default function AccountSecurityPage() {
  const { t } = useTranslation();
  const unavailable = (): never => { throw new Error(t('security.backendRequired')); };
  const navigate = useNavigate();
  const status = useApiQuery('account-mfa', () => callApi<{ enabled: boolean; required: boolean; passwordRequired: boolean }>(
    '/api/v1/auth/mfa', unavailable, { noFallback: true }));
  const [setup, setSetup] = useState<{ secret: string; uri: string }>();
  const [recovery, setRecovery] = useState<string[]>();
  const [busy, setBusy] = useState(false);
  const [form] = Form.useForm<{ currentPassword: string; code: string }>();
  const passwordRequired = status.data?.data.passwordRequired !== false;
  const logout = () => { void logoutSession().then(() => navigate('/login', { replace: true })); };

  const generate = async () => {
    try {
      const values = await form.validateFields(passwordRequired ? ['currentPassword'] : []);
      setBusy(true);
      const result = await callApi<{ secret: string; uri: string }>('/api/v1/auth/mfa/setup', unavailable,
        { method: 'POST', body: { current_password: values.currentPassword }, noFallback: true });
      setSetup(result.data);
      form.setFieldValue('currentPassword', '');
    } catch (error) { if (error instanceof Error) message.error(error.message); }
    finally { setBusy(false); }
  };
  const confirm = async () => {
    try {
      const values = await form.validateFields(['code']);
      setBusy(true);
      const result = await callApi<{ recoveryCodes: string[] }>('/api/v1/auth/mfa/confirm', unavailable,
        { method: 'POST', body: { code: values.code }, noFallback: true });
      setRecovery(result.data.recoveryCodes);
      setSetup(undefined);
      form.resetFields();
      // Confirmation revokes this session; keep the one-time recovery codes visible until logout.
    } catch (error) { if (error instanceof Error) message.error(error.message); }
    finally { setBusy(false); }
  };
  const disable = async () => {
    try {
      const values = await form.validateFields();
      setBusy(true);
      await callApi('/api/v1/auth/mfa/disable', unavailable, { method: 'POST', noFallback: true,
        body: { current_password: values.currentPassword, code: values.code } });
      form.resetFields();
      message.success(t('security.disabledRelogin'));
      logout();
    } catch (error) { if (error instanceof Error) message.error(error.message); }
    finally { setBusy(false); }
  };
  return <main style={{ maxWidth: 760, padding: 24, margin: '0 auto' }}>
    <PageHeader title={t('nav.security')} subtitle={t('security.subtitle')} actions={<Space>
      <Link to="/">{t('security.back')}</Link><Button onClick={logout}>{t('layout.logout')}</Button>
    </Space>} />
    <DataState loading={status.isLoading} error={status.error}>
      <Card>
        {status.data?.data.required && <Alert type="info" showIcon message={t('security.mfaRequired')} style={{ marginBottom: 16 }} />}
        <Typography.Paragraph>{t('security.mfaStatus')} {status.data?.data.enabled ? t('security.enabled') : t('security.notLinked')}</Typography.Paragraph>
        {!passwordRequired && <Alert type="info" showIcon message={t('security.ssoRecent')} />}
        {recovery ? <Space direction="vertical" style={{ width: '100%' }}>
          <Alert type="warning" message={t('security.recoveryWarning')} />
          <Typography.Paragraph copyable={{ text: recovery.join('\n') }} style={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>{recovery.join('\n')}</Typography.Paragraph>
          <Button type="primary" onClick={logout}>{t('security.savedRelogin')}</Button>
        </Space> : <Form form={form} layout="vertical">
          {!setup && passwordRequired && <Form.Item name="currentPassword" label={t('security.currentPassword')} rules={[{ required: true }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>}
          {setup && <>
            <Alert type="info" message={t('security.setupHint')} />
            <QRCode value={setup.uri} bgColor="#ffffff" style={{ margin: '16px 0' }} />
            <Typography.Paragraph copyable>{setup.secret}</Typography.Paragraph>
          </>}
          {(setup || status.data?.data.enabled) && <Form.Item name="code" label={t('security.code')} rules={[{ required: true }]}>
            <Input autoComplete="one-time-code" maxLength={32} />
          </Form.Item>}
          {setup ? <Button type="primary" loading={busy} onClick={() => void confirm()}>{t('security.confirm')}</Button>
            : status.data?.data.enabled ? <Button danger disabled={status.data.data.required} loading={busy} onClick={() => void disable()}>{t('security.disable')}</Button>
              : <Button type="primary" loading={busy} onClick={() => void generate()}>{passwordRequired ? t('security.verifyGenerate') : t('security.generate')}</Button>}
        </Form>}
      </Card>
    </DataState>
  </main>;
}
