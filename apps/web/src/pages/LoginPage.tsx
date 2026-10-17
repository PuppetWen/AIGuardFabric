import { useEffect, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import { Alert, Button, Card, Divider, Form, Input, Space, Tag, Typography, message } from 'antd';
import { LockOutlined, SafetyOutlined, ShopOutlined, UserOutlined } from '@ant-design/icons';

import { DemoModeBanner } from '@/components/DemoModeBanner';
import { DEMO_CREDENTIALS, api, demoLogin, probeBackend } from '@/api/client';
import { useAuthStore } from '@/stores/authStore';
import type { PasswordPolicy } from '@/types/domain';
import { FALLBACK_POLICY, checkPasswordPolicy } from './login/passwordPolicy';
import { SsoButton } from './login/SsoButton';
import { SamlButton } from './login/SamlButton';
import { QrLoginButton } from './login/QrLoginButton';
import { ssoApi } from '@/api/sso';

/**
 * 真实后端（`agf-server`）的登录名与租户。
 *
 * **口令不在前端**：它由部署端生成并写在 `.env` 的 `AGF_BOOTSTRAP_ADMIN_PASSWORD`
 * （留空时由服务端随机生成并落日志/文件），首次登录会强制改密。因此这里只提供
 * "填入用户名"，绝不臆造口令——演示口令只对离线演示数据有效。
 */
const PLATFORM_CREDENTIALS = { tenantSlug: 'default', username: 'admin' } as const;

interface LoginFormValues {
  tenantSlug: string;
  username: string;
  password: string;
  mfaCode?: string;
}

interface ChangePasswordValues {
  newPassword: string;
  confirmPassword: string;
}

interface PendingSession {
  token: string;
  mustChangePassword: boolean;
  tenantSlug: string;
  username: string;
  currentPassword: string;
}

export default function LoginPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const token = useAuthStore((state) => state.token);
  const sessionExpired = useAuthStore((state) => state.sessionExpired);
  const setSession = useAuthStore((state) => state.setSession);

  const [submitting, setSubmitting] = useState(false);
  const [pending, setPending] = useState<PendingSession | null>(null);
  const [policy, setPolicy] = useState<PasswordPolicy>(FALLBACK_POLICY);
  const [error, setError] = useState<string | null>(null);
  const [demoHint, setDemoHint] = useState(true);
  /** 登录表单实例：凭据面板的"填入"按钮必须真的写进表单，不能只弹个 toast。 */
  const [form] = Form.useForm<LoginFormValues>();
  /** `null` = 探测中；`true` = 已连接真实后端；`false` = 后端不可达（离线演示）。 */
  const [backendLive, setBackendLive] = useState<boolean | null>(null);

  const from = (location.state as { from?: string } | null)?.from ?? '/';

  // 探测后端：真实后端在跑时**绝不能**把演示口令摆出来当"可用凭据"
  // （实测踩过：用户照着一键填充的 admin/Admin@12345 登录，只会拿到 401）。
  useEffect(() => {
    let cancelled = false;
    void probeBackend().then((live) => {
      if (cancelled) {
        return;
      }
      setBackendLive(live);
      // A delayed health probe must never overwrite fields the user has already edited.
      const defaults = live ? PLATFORM_CREDENTIALS : DEMO_CREDENTIALS;
      for (const name of ['tenantSlug', 'username'] as const) {
        if (!form.isFieldTouched(name)) form.setFieldValue(name, defaults[name]);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [form]);

  const fillCredentials = (values: Partial<LoginFormValues>, toast: string): void => {
    form.setFieldsValue(values);
    message.info(toast);
  };

  if (token && !pending) {
    return <Navigate to={from} replace />;
  }

  const handleLogin = async (values: LoginFormValues, method: 'local' | 'ldap' = 'local'): Promise<void> => {
    setSubmitting(true);
    setError(null);
    try {
      const credentials = {
        tenantSlug: values.tenantSlug.trim(),
        username: values.username.trim(),
        password: values.password,
        mfaCode: values.mfaCode?.trim() || undefined,
      };
      const result = method === 'ldap' ? await ssoApi.ldapLogin(credentials) : await api.login(credentials);

      setPolicy(result.data.passwordPolicy ?? FALLBACK_POLICY);

      const { token: nextToken, user, tenant, mustChangePassword } = result.data;

      if (mustChangePassword) {
        setPending({
          token: nextToken,
          mustChangePassword,
          tenantSlug: values.tenantSlug.trim(),
          username: values.username.trim(),
          currentPassword: values.password,
        });
        return;
      }

      setSession({
        token: nextToken,
        refreshToken: result.data.refreshToken,
        tenant,
        displayName: user.displayName,
        role: user.role,
        mustChangePassword: false,
      });
      message.success(t('login.welcome', { name: user.displayName }));
      navigate(result.data.mfaEnrollmentRequired ? '/security' : from, { replace: true });
    } catch (caught) {
      const detail = caught instanceof Error ? caught.message : String(caught);
      setError(`${t('login.failed')}：${detail}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleChangePassword = async (values: ChangePasswordValues): Promise<void> => {
    if (!pending) {
      return;
    }
    if (values.newPassword !== values.confirmPassword) {
      setError(t('login.passwordMismatch'));
      return;
    }
    const violation = checkPasswordPolicy(values.newPassword, policy);
    if (violation) {
      setError(t('login.passwordWeak', { min: policy.minLength }));
      return;
    }

    setSubmitting(true);
    try {
      await api.changePassword({
        token: pending.token,
        currentPassword: pending.currentPassword,
        newPassword: values.newPassword,
      });

      // 改密成功后必须**重新登录**换取会话令牌：`pending.token` 是一次性 change_token，
      // 拿它当会话令牌会被后端判 401（此前这里直接用 demoLogin 造会话，联调时必挂）。
      const relogin = await api.login({
        tenantSlug: pending.tenantSlug,
        username: pending.username,
        password: values.newPassword,
      });

      if (relogin.meta.source === 'live' && relogin.data.token) {
        setSession({
          token: relogin.data.token,
          refreshToken: relogin.data.refreshToken,
          tenant: relogin.data.tenant,
          displayName: relogin.data.user.displayName,
          role: relogin.data.user.role,
          mustChangePassword: false,
        });
      } else {
        // 演示模式（后端不可达）：沿用原有的本地会话构造，保证离线流程仍可走完。
        const session = demoLogin({
          tenantSlug: pending.tenantSlug,
          username: pending.username,
          password: values.newPassword,
        });
        setSession({
          token: pending.token,
          tenant: session.tenant,
          displayName: session.user.displayName,
          role: session.user.role,
          mustChangePassword: false,
        });
      }
      message.success(t('login.changeSuccess'));
      setPending(null);
      navigate(relogin.data.mfaEnrollmentRequired ? '/security' : from, { replace: true });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="agf-login">
      <div className="agf-login__grid">
        <div className="agf-login__aside">
          <Space size={10} align="center">
            <span className="agf-brand__mark" aria-hidden>
              AGF
            </span>
            <Typography.Text strong style={{ fontSize: 16 }}>
              {t('app.name')} · {t('app.nameEn')}
            </Typography.Text>
          </Space>
          <h1 className="agf-login__hero">{t('login.title')}</h1>
          <Typography.Paragraph type="secondary" style={{ margin: 0, fontSize: 14 }}>
            {t('login.subtitle')}
          </Typography.Paragraph>
          <div className="agf-login__features">
            {(
              [
                'assets.subtitle',
                'findings.subtitle',
                'redteam.subtitle',
                'runtime.subtitle',
              ] as const
            ).map((key) => (
              <div className="agf-login__feature" key={key}>
                <SafetyOutlined style={{ color: 'var(--agf-accent)', marginTop: 3 }} />
                <span>{t(key)}</span>
              </div>
            ))}
          </div>
          <Space size={8} wrap>
            <Tag color="blue">资产发现</Tag>
            <Tag color="geekblue">风险检测</Tag>
            <Tag color="purple">运行时策略</Tag>
            <Tag color="cyan">MCP</Tag>
            <Tag color="gold">AgentTeams</Tag>
          </Space>
        </div>

        <Card className="agf-login__card" bordered={false}>
          <DemoModeBanner />
          {sessionExpired && <Alert type="warning" showIcon message={t('login.sessionExpired', {
            defaultValue: '登录已过期或被撤销，请重新登录后继续。',
          })} />}
          <Typography.Title level={4} style={{ marginTop: 0, marginBottom: 4 }}>
            {pending ? t('login.firstLoginTitle') : t('app.name')}
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 13 }}>
            {pending ? t('login.firstLoginHint') : t('app.tagline')}
          </Typography.Text>

          {error ? (
            <Alert
              style={{ marginTop: 14 }}
              type="error"
              showIcon
              message={t('login.failed')}
              description={error}
              closable
              onClose={() => setError(null)}
            />
          ) : null}

          {pending ? (
            <Form<ChangePasswordValues>
              layout="vertical"
              style={{ marginTop: 16 }}
              requiredMark={false}
              onFinish={(values) => {
                void handleChangePassword(values);
              }}
            >
              <Form.Item
                name="newPassword"
                label={t('login.newPassword')}
                rules={[
                  { required: true, message: t('login.newPasswordRequired') },
                  {
                    validator: (_rule, value: string) =>
                      checkPasswordPolicy(value ?? '', policy)
                        ? Promise.reject(new Error(t('login.passwordWeak', { min: policy.minLength })))
                        : Promise.resolve(),
                  },
                ]}
              >
                <Input.Password
                  autoFocus
                  prefix={<LockOutlined />}
                  placeholder={t('settings.password.ruleHint', { min: policy.minLength })}
                />
              </Form.Item>
              <Form.Item
                name="confirmPassword"
                label={t('login.confirmPassword')}
                dependencies={['newPassword']}
                rules={[
                  { required: true, message: t('login.confirmRequired') },
                  ({ getFieldValue }) => ({
                    validator: (_rule, value: string) =>
                      value === getFieldValue('newPassword')
                        ? Promise.resolve()
                        : Promise.reject(new Error(t('login.passwordMismatch'))),
                  }),
                ]}
              >
                <Input.Password prefix={<LockOutlined />} />
              </Form.Item>
              <Space>
                <Button type="primary" htmlType="submit" loading={submitting} block>
                  {t('login.changePassword')}
                </Button>
                <Button onClick={() => setPending(null)}>{t('common.cancel')}</Button>
              </Space>
            </Form>
          ) : (
            <Form<LoginFormValues>
              form={form}
              layout="vertical"
              style={{ marginTop: 16 }}
              requiredMark={false}
              initialValues={{
                tenantSlug: PLATFORM_CREDENTIALS.tenantSlug,
                username: PLATFORM_CREDENTIALS.username,
              }}
              onFinish={(values) => {
                void handleLogin(values);
              }}
            >
              <Form.Item
                name="tenantSlug"
                label={t('login.tenant')}
                rules={[{ required: true, message: t('login.tenantRequired') }]}
              >
                <Input
                  prefix={<ShopOutlined />}
                  placeholder={t('login.tenantPlaceholder')}
                  autoComplete="organization"
                />
              </Form.Item>
              <Form.Item
                name="username"
                label={t('login.username')}
                rules={[{ required: true, message: t('login.usernameRequired') }]}
              >
                <Input
                  prefix={<UserOutlined />}
                  placeholder={t('login.usernamePlaceholder')}
                  autoComplete="username"
                />
              </Form.Item>
              <Form.Item
                name="password"
                label={t('login.password')}
                rules={[{ required: true, message: t('login.passwordRequired') }]}
              >
                <Input.Password
                  prefix={<LockOutlined />}
                  placeholder={t('login.passwordPlaceholder')}
                  autoComplete="current-password"
                />
              </Form.Item>
              <Form.Item name="mfaCode" label={t('login.mfa')} extra={t('login.mfaHint')}>
                <Input
                  prefix={<SafetyOutlined />}
                  placeholder={t('login.mfaPlaceholder')}
                  maxLength={6}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                />
              </Form.Item>

              <Button type="primary" htmlType="submit" loading={submitting} block size="large">
                {submitting ? t('login.submitting') : t('login.submit')}
              </Button>
              {backendLive && <SsoButton tenant={() => form.getFieldValue('tenantSlug')} />}
              {backendLive && <SamlButton tenant={() => form.getFieldValue('tenantSlug')} />}
              {backendLive && <QrLoginButton tenant={() => form.getFieldValue('tenantSlug')} />}
              {backendLive && <Button block loading={submitting} style={{ marginTop: 8 }} onClick={() => {
                void form.validateFields(['tenantSlug', 'username', 'password'])
                  .then(() => handleLogin(form.getFieldsValue(), 'ldap')).catch(() => undefined);
              }}>LDAP / AD {t('login.submit')}</Button>}
            </Form>
          )}

          <Divider plain style={{ marginBlock: 14 }}>
            <span className="agf-tertiary" style={{ fontSize: 12 }}>
              {backendLive ? t('login.platformTitle') : t('login.demoTitle')}
            </span>
          </Divider>

          {backendLive ? (
            <Alert
              type="info"
              showIcon
              message={t('login.platformNotice')}
              description={
                <Space direction="vertical" size={2} style={{ fontSize: 12 }}>
                  <span>
                    {t('login.demoUser')}：<code className="agf-mono">{PLATFORM_CREDENTIALS.username}</code>
                  </span>
                  <span>{t('login.platformPasswordHint')}</span>
                  <span>{t('login.platformFirstLogin')}</span>
                  <Button
                    size="small"
                    type="link"
                    style={{ paddingInline: 0 }}
                    onClick={() =>
                      fillCredentials(
                        { tenantSlug: PLATFORM_CREDENTIALS.tenantSlug, username: PLATFORM_CREDENTIALS.username },
                        t('login.fillPlatformUser'),
                      )
                    }
                  >
                    {t('login.fillPlatformUser')}
                  </Button>
                </Space>
              }
            />
          ) : demoHint ? (
            <Alert
              type={backendLive === false ? 'warning' : 'info'}
              showIcon
              closable
              onClose={() => setDemoHint(false)}
              message={t('login.demoNotice')}
              description={
                <Space direction="vertical" size={2} style={{ fontSize: 12 }}>
                  <span>
                    {t('login.demoTenant')}：<code className="agf-mono">{DEMO_CREDENTIALS.tenantSlug}</code>
                  </span>
                  <span>
                    {t('login.demoUser')}：<code className="agf-mono">{DEMO_CREDENTIALS.username}</code>
                  </span>
                  <span>
                    {t('login.demoPassword')}：
                    <code className="agf-mono">{DEMO_CREDENTIALS.password}</code>
                  </span>
                  <span>
                    {t('login.demoMfa')}：{t('login.demoMfaValue')}
                  </span>
                  <Button
                    size="small"
                    type="link"
                    style={{ paddingInline: 0 }}
                    onClick={() =>
                      fillCredentials(
                        {
                          tenantSlug: DEMO_CREDENTIALS.tenantSlug,
                          username: DEMO_CREDENTIALS.username,
                          password: DEMO_CREDENTIALS.password,
                        },
                        t('login.demoFilled'),
                      )
                    }
                  >
                    {t('login.demoFill')}
                  </Button>
                </Space>
              }
            />
          ) : null}

          <Typography.Paragraph className="agf-tertiary" style={{ fontSize: 12, marginTop: 12, marginBottom: 0 }}>
            {t('login.ssoHint')}
          </Typography.Paragraph>
        </Card>
      </div>
    </div>
  );
}
