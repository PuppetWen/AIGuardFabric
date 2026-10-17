import { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Form, Input, Popconfirm, Select, Space, Spin, Switch, Typography, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { ssoApi, type SamlSettings } from '@/api/sso';
import { ApiRequestError } from '@/api/transport';
import { useAuthStore } from '@/stores/authStore';

export function SamlTab({ canWrite }: { canWrite: boolean }) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const label = (cn: string, en: string) => zh ? cn : en;
  const slug = useAuthStore((s) => s.tenant?.slug) ?? 'default';
  const root = `${window.location.origin}/api/v1/auth/saml/${encodeURIComponent(slug)}`;
  const [form] = Form.useForm<SamlSettings>();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [conflict, setConflict] = useState(false);
  const [configured, setConfigured] = useState(false);
  const revision = useRef<string | null>(null);
  const fill = useCallback((data: SamlSettings) => {
    form.setFieldsValue({ ...data, spEntityId: data.spEntityId || `${root}/metadata`,
      acsUrl: data.acsUrl || `${root}/acs` });
    revision.current = data.revision;
    setConfigured(Boolean(data.revision));
  }, [form, root]);
  useEffect(() => {
    let active = true;
    void ssoApi.samlSettings().then(({ data }) => { if (active) fill(data); })
      .catch((e: Error) => { if (active) setError(e.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [fill]);
  const save = async (values: SamlSettings, rotate = false) => {
    if (!canWrite || conflict) return;
    setSaving(true); setError('');
    try {
      const { data } = await ssoApi.saveSaml(values, revision.current, rotate);
      fill(data);
      message.success(label('SAML 配置已保存', 'SAML settings saved'));
    } catch (e) {
      setConflict(e instanceof ApiRequestError && e.status === 409);
      setError(e instanceof Error ? e.message : String(e));
    } finally { setSaving(false); }
  };
  return <Spin spinning={loading}><Space direction="vertical" style={{ width: '100%', maxWidth: 850 }}>
    <Alert showIcon type="info" message={label('接入企业 SAML 2.0', 'Connect enterprise SAML 2.0')}
      description={label(
        '1. 在身份服务创建 SAML 应用，填入下面的 SP Entity ID 和 ACS URL。2. 从身份服务复制 IdP 元数据 XML 粘贴到表单；请确认含签名证书与 HTTP-Redirect 登录地址。3. 保存并启用，先用只读测试成员登录。平台要求签名响应、匹配请求与一次性状态，并继续执行本平台 MFA。',
        '1. Create a SAML app at your identity provider using the SP Entity ID and ACS URL below. 2. Paste the IdP metadata XML, including a signing certificate and HTTP-Redirect SSO endpoint. 3. Save and enable, then test with a viewer. Signed responses, request correlation, one-time state, and platform MFA are enforced.')} />
    {error && <Alert showIcon type="error" message={error} description={conflict
      ? label('草稿仍在表单中；复制要保留的修改，再加载最新配置。', 'Your draft remains in the form. Copy any changes before reloading.') : undefined} />}
    {conflict && <Popconfirm title={label('丢弃草稿并加载最新配置？', 'Discard draft and reload settings?')}
      onConfirm={async () => {
        try { const { data } = await ssoApi.samlSettings(); fill(data); setConflict(false); setError(''); }
        catch (e) { setError(e instanceof Error ? e.message : String(e)); }
      }}><Button>{label('加载最新配置', 'Reload settings')}</Button></Popconfirm>}
    <Form form={form} layout="vertical" disabled={loading || saving || !canWrite}
      onFinish={(values) => void save(values)}>
      <Form.Item name="enabled" label={label('启用 SAML 登录', 'Enable SAML sign-in')} valuePropName="checked"><Switch /></Form.Item>
      <Form.Item name="name" label={label('身份服务名称', 'Identity provider name')} rules={[{ required: true }]}>
        <Input maxLength={128} placeholder={label('公司 SAML 身份服务', 'Company SAML identity provider')} />
      </Form.Item>
      <Form.Item name="spEntityId" label="SP Entity ID / Metadata URL" rules={[{ required: true }, { type: 'url' }]}
        extra={label('将此值填入 IdP 的应用标识；保存后可打开该地址下载 SP 元数据。',
          'Use this value as the application identifier at the IdP. Open it after saving to download SP metadata.')}>
        <Input />
      </Form.Item>
      <Form.Item name="acsUrl" label="ACS URL" rules={[{ required: true }, { type: 'url' }]}
        extra={label('填入 IdP 的 Assertion Consumer Service / 回复地址；应与实际控制台地址同源。',
          'Use this as the Assertion Consumer Service or reply URL at the IdP, on the actual console origin.')}>
        <Input />
      </Form.Item>
      <Form.Item name="idpMetadataXml" label={label('IdP 元数据 XML', 'IdP metadata XML')}
        extra={label('仅从可信的身份服务管理员页面复制；平台不会从元数据中的 URL 自动抓取或信任证书轮换。',
          'Copy from your trusted IdP administration page. The platform never auto-fetches metadata or trusts certificate changes from a URL.')}>
        <Input.TextArea rows={8} maxLength={131072} placeholder="<EntityDescriptor ...>" />
      </Form.Item>
      <Form.Item name="emailAttribute" label={label('邮箱属性名', 'Email attribute name')} rules={[{ required: true }]}>
        <Input placeholder="email" />
      </Form.Item>
      <Form.Item name="nameAttribute" label={label('显示名属性名', 'Display-name attribute')} rules={[{ required: true }]}>
        <Input placeholder="displayName" />
      </Form.Item>
      <Form.Item name="emailDomains" label={label('允许的邮箱域名（可选）', 'Allowed email domains (optional)')}
        extra={label('配置后，没有匹配邮箱域名的身份会被拒绝。', 'When set, identities without a matching email domain are rejected.')}>
        <Select mode="tags" tokenSeparators={[',', ';', ' ']} placeholder="example.com" />
      </Form.Item>
      <Form.Item name="autoProvision" label={label('首次登录自动创建账号', 'Create account on first sign-in')}
        valuePropName="checked" extra={label('按 IdP Entity ID 与 NameID 绑定；请在身份服务中使用不可变 NameID。',
          'Accounts are bound to the IdP Entity ID and NameID. Configure an immutable NameID at the IdP.')}><Switch /></Form.Item>
      <Form.Item name="defaultRole" label={label('新账号默认角色', 'Default role for new accounts')}>
        <Select options={[{ value: 'viewer', label: label('只读用户（推荐）', 'Viewer (recommended)') },
          { value: 'auditor', label: label('审计员', 'Auditor') },
          { value: 'soc-analyst', label: label('安全分析员', 'Security analyst') },
          { value: 'asset-owner', label: label('资产负责人', 'Asset owner') }]} />
      </Form.Item>
      <Space>
        <Button type="primary" htmlType="submit" loading={saving} disabled={!canWrite || conflict}>
          {label('保存 SAML 配置', 'Save SAML settings')}</Button>
        {configured && <Popconfirm title={label('轮换后须立即在 IdP 更新 SP 证书，旧请求会失效。确定轮换？',
          'Update the SP certificate at the IdP immediately; pending requests will expire. Rotate?')}
          onConfirm={() => void form.validateFields().then((values) => save(values, true)).catch(() => undefined)}>
          <Button disabled={!canWrite || conflict || saving}>{label('轮换 SP 证书', 'Rotate SP certificate')}</Button>
        </Popconfirm>}
      </Space>
    </Form>
    {configured && <Typography.Link href={`${root}/metadata`} target="_blank" rel="noreferrer">
      {label('下载 SP 元数据', 'Download SP metadata')}
    </Typography.Link>}
    <Typography.Paragraph type="secondary">{label('请使用 HTTPS 控制台域名；仅本机回环联调允许 HTTP。',
      'Use an HTTPS console URL. HTTP is only supported on a local loopback address.')}</Typography.Paragraph>
  </Space></Spin>;
}
