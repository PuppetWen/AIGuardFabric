import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Alert, Button, Modal, QRCode, Space, Typography, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { ssoApi, type QrFlow } from '@/api/sso';
import { useAuthStore } from '@/stores/authStore';

export function QrLoginButton({ tenant }: { tenant: () => string }) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const label = (cn: string, en: string) => zh ? cn : en;
  const navigate = useNavigate();
  const setSession = useAuthStore((s) => s.setSession);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [flow, setFlow] = useState<QrFlow | null>(null);
  const [error, setError] = useState('');
  const redeeming = useRef(false);
  const start = async () => {
    const tenantSlug = tenant()?.trim();
    if (!tenantSlug) { message.error(label('请先填写租户标识', 'Enter the tenant first')); return; }
    setLoading(true); setError(''); setFlow(null); redeeming.current = false;
    try {
      const { data } = await ssoApi.qrStart(tenantSlug);
      setFlow({ tenantSlug, state: data.state, binding: data.binding, expiresAt: data.expiresAt });
      setOpen(true);
    } catch (caught) {
      message.error(caught instanceof Error ? caught.message : String(caught));
    } finally { setLoading(false); }
  };
  useEffect(() => {
    if (!open || !flow) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      if (Date.now() >= flow.expiresAt * 1000) {
        if (active) setError(zh ? '二维码已过期，请重新生成' : 'QR code expired. Generate a new one.');
        return;
      }
      try {
        const { data } = await ssoApi.qrStatus(flow);
        if (!active) return;
        if (data.status === 'approved' && !redeeming.current) {
          redeeming.current = true;
          const session = await ssoApi.qrComplete(flow);
          if (!active) return;
          if (!session.token) throw new Error(zh ? '登录响应缺少会话令牌' : 'Session token missing');
          setSession({ token: session.token, refreshToken: session.refreshToken, tenant: session.tenant,
            displayName: session.user.displayName, role: session.user.role, mustChangePassword: false });
          setOpen(false);
          navigate(session.mfaEnrollmentRequired ? '/security' : '/', { replace: true });
          return;
        }
      } catch (caught) {
        if (active) setError(caught instanceof Error ? caught.message : String(caught));
        return;
      }
      if (active) timer = setTimeout(() => { void poll(); }, 2000);
    };
    timer = setTimeout(() => { void poll(); }, 1000);
    return () => { active = false; clearTimeout(timer); };
  }, [flow, open, navigate, setSession, zh]);
  const approvalUrl = flow ? `${window.location.origin}/login/qr/approve?tenant=${encodeURIComponent(flow.tenantSlug)}&state=${encodeURIComponent(flow.state)}` : '';
  return <>
    <Button block loading={loading} onClick={() => void start()} style={{ marginTop: 8 }}>
      {label('手机扫码登录', 'Sign in with phone QR code')}
    </Button>
    <Modal open={open} title={label('手机确认登录', 'Approve sign-in on your phone')} footer={null}
      onCancel={() => { setOpen(false); setFlow(null); }}>
      <Space direction="vertical" align="center" style={{ width: '100%' }}>
        <Typography.Paragraph>{label(
          '请用已登录同一租户的手机打开二维码，在手机上输入平台 MFA 验证码并确认。二维码 3 分钟后过期。',
          'Scan with a phone signed in to the same tenant, enter your platform MFA code, and approve. The QR code expires in 3 minutes.')}</Typography.Paragraph>
        {flow && <QRCode value={approvalUrl} size={210} bgColor="#ffffff" />}
        <Typography.Text copyable={{ text: approvalUrl }} style={{ maxWidth: '100%', wordBreak: 'break-all' }}>
          {label('复制手机确认链接', 'Copy phone approval link')}
        </Typography.Text>
        {error ? <Alert showIcon type="error" message={error} />
          : <Typography.Text type="secondary">{label('等待手机批准…', 'Waiting for phone approval…')}</Typography.Text>}
        {error && <Button onClick={() => void start()} loading={loading}>{label('重新生成二维码', 'Generate a new QR code')}</Button>}
      </Space>
    </Modal>
  </>;
}
