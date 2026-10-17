import { useEffect, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { Alert, Button, Card, Form, Input, Space, Spin, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { ssoApi } from '@/api/sso';
import { useAuthStore } from '@/stores/authStore';

export default function QrApprovePage() {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const label = (cn: string, en: string) => zh ? cn : en;
  const navigate = useNavigate();
  const location = useLocation();
  const token = useAuthStore((s) => s.token);
  const displayName = useAuthStore((s) => s.displayName);
  const params = new URLSearchParams(location.search);
  const tenantSlug = params.get('tenant') ?? '';
  const state = params.get('state') ?? '';
  const invalidLink = !tenantSlug || !state;
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [approved, setApproved] = useState(false);
  const [error, setError] = useState('');
  const [previewName, setPreviewName] = useState('');
  useEffect(() => {
    if (!token) return;
    if (invalidLink) return;
    let active = true;
    void ssoApi.qrPreview(tenantSlug, state).then(({ data }) => {
      if (active) { setPreviewName(data.userName); setApproved(data.status === 'approved'); }
    }).catch((caught: Error) => { if (active) setError(caught.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [token, tenantSlug, state, invalidLink]);
  if (!token) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  const approve = async ({ code }: { code: string }) => {
    setSaving(true); setError('');
    try {
      await ssoApi.qrApprove(tenantSlug, state, code.trim());
      setApproved(true);
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)); }
    finally { setSaving(false); }
  };
  return <Card style={{ maxWidth: 540, margin: '9vh auto' }}><Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={3}>{label('批准新浏览器登录', 'Approve a new browser sign-in')}</Typography.Title>
    <Typography.Paragraph>{label(
      '只有你刚才主动在新浏览器请求登录时才批准。二维码只包含一次性请求编号；登录令牌不会传给手机。',
      'Approve only if you requested sign-in in another browser. The QR code contains a one-time request ID, never a login token.')}</Typography.Paragraph>
    <Typography.Text>{label('租户', 'Tenant')}: <strong>{tenantSlug}</strong></Typography.Text>
    <Typography.Text>{label('当前账号', 'Current account')}: <strong>{previewName || displayName}</strong></Typography.Text>
    {loading && !invalidLink && <Spin />}
    {(error || invalidLink) && <Alert showIcon type="error" message={error || label('二维码链接不完整', 'Invalid QR link')} description={label(
      '请确认手机已登录同一租户、账号已启用平台 MFA，且二维码没有过期。',
      'Check the phone is signed in to the same tenant, platform MFA is enabled, and the QR code has not expired.')} />}
    {approved ? <Alert showIcon type="success" message={label('已批准，请返回新浏览器', 'Approved. Return to the new browser.')} />
      : !loading && !invalidLink && <Form layout="vertical" onFinish={(values) => void approve(values)}>
        <Form.Item name="code" label={label('平台 MFA 验证码或恢复码', 'Platform MFA or recovery code')}
          rules={[{ required: true }]}><Input autoComplete="one-time-code" /></Form.Item>
        <Button type="primary" htmlType="submit" loading={saving} block>
          {label('批准这次登录', 'Approve this sign-in')}
        </Button>
      </Form>}
    {error && <Button onClick={() => navigate('/security')}>{label('设置平台 MFA', 'Set up platform MFA')}</Button>}
    <Button onClick={() => navigate('/', { replace: true })}>{label('返回控制台', 'Back to console')}</Button>
  </Space></Card>;
}
