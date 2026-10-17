import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Card, Form, Input, Space, Spin, Typography } from 'antd';
import { SAML_STORAGE_KEY, ssoApi, type SamlFlow } from '@/api/sso';
import { useAuthStore } from '@/stores/authStore';
import type { LoginResponse } from '@/types/domain';

function callbackFlow(zh: boolean): SamlFlow {
  const params = new URLSearchParams(window.location.search);
  window.history.replaceState(null, '', window.location.pathname);
  const raw = sessionStorage.getItem(SAML_STORAGE_KEY);
  if (!raw) throw new Error(zh ? 'SAML 登录未在此浏览器标签页发起'
    : 'SAML sign-in was not started in this browser tab.');
  const flow = JSON.parse(raw) as SamlFlow;
  if (flow.state !== params.get('state') || flow.tenantSlug !== params.get('tenant')
    || Date.now() - flow.createdAt > 600000) {
    throw new Error(zh ? 'SAML 登录状态不匹配或已过期，请重新发起'
      : 'SAML sign-in expired or its state did not match. Start again.');
  }
  return flow;
}

export default function SamlCallbackPage() {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const navigate = useNavigate();
  const setSession = useAuthStore((s) => s.setSession);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(true);
  const [challenge, setChallenge] = useState<SamlFlow | null>(null);
  const job = useRef<Promise<LoginResponse | SamlFlow> | null>(null);
  const accept = useCallback((session: LoginResponse) => {
    if (!session.token) throw new Error(zh ? '登录响应缺少会话令牌' : 'Session token missing');
    sessionStorage.removeItem(SAML_STORAGE_KEY);
    setSession({ token: session.token, refreshToken: session.refreshToken, tenant: session.tenant,
      displayName: session.user.displayName, role: session.user.role, mustChangePassword: false });
    navigate(session.mfaEnrollmentRequired ? '/security' : '/', { replace: true });
  }, [navigate, setSession, zh]);
  useEffect(() => {
    let active = true;
    job.current ??= (async () => {
      const flow = callbackFlow(zh);
      const { data } = await ssoApi.samlStatus(flow);
      return data.mfaRequired ? flow : ssoApi.samlComplete(flow);
    })();
    void job.current.then((result) => {
      if (!active) return;
      if ('binding' in result) setChallenge(result);
      else accept(result);
    }).catch((e: Error) => { if (active) setError(e.message); })
      .finally(() => { if (active) setBusy(false); });
    return () => { active = false; };
  }, [accept, zh]);
  const complete = async ({ code }: { code: string }) => {
    if (!challenge) return;
    setBusy(true); setError('');
    try { accept(await ssoApi.samlComplete(challenge, code)); }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  };
  return <Card style={{ maxWidth: 520, margin: '12vh auto' }}><Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={3}>{zh ? '企业 SAML 身份验证' : 'Enterprise SAML sign-in'}</Typography.Title>
    {busy && <Spin tip={zh ? '正在验证企业身份' : 'Verifying identity'}><div style={{ height: 64 }} /></Spin>}
    {error && <Alert type="error" showIcon message={error} />}
    {challenge && <Form onFinish={(values) => void complete(values)} layout="vertical">
      <Form.Item name="code" label={zh ? '本平台 MFA 验证码或恢复码' : 'Platform MFA or recovery code'}
        rules={[{ required: true }]}><Input autoComplete="one-time-code" autoFocus /></Form.Item>
      <Button type="primary" htmlType="submit" loading={busy}>{zh ? '完成登录' : 'Complete sign-in'}</Button>
    </Form>}
    <Button onClick={() => { sessionStorage.removeItem(SAML_STORAGE_KEY); navigate('/login', { replace: true }); }}>
      {zh ? '返回登录' : 'Back to sign-in'}</Button>
  </Space></Card>;
}
