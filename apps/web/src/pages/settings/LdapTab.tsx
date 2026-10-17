import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Form, Input, Popconfirm, Select, Space, Spin, Switch, Typography, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { ssoApi, type LdapSettings } from '@/api/sso';
import { ApiRequestError } from '@/api/transport';

export function LdapTab({ canWrite }: { canWrite: boolean }) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const label = (cn: string, en: string) => zh ? cn : en;
  const [form] = Form.useForm<LdapSettings>();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [conflict, setConflict] = useState(false);
  const [configured, setConfigured] = useState(false);
  const revision = useRef<string | null>(null);
  useEffect(() => {
    let active = true;
    void ssoApi.ldapSettings().then(({ data }) => {
      if (active) {
        form.setFieldsValue(data);
        revision.current = data.revision;
        setConfigured(data.credentialConfigured);
      }
    }).catch((e: Error) => { if (active) setError(e.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [form]);
  const save = async (values: LdapSettings) => {
    if (!canWrite || conflict) return;
    setSaving(true); setError('');
    try {
      const { data } = await ssoApi.saveLdap(values, revision.current);
      form.setFieldsValue({ ...data, bindPassword: undefined });
      revision.current = data.revision;
      setConfigured(data.credentialConfigured);
      message.success(label('目录登录配置已保存', 'Directory sign-in settings saved'));
    } catch (e) {
      setConflict(e instanceof ApiRequestError && e.status === 409);
      setError(e instanceof Error ? e.message : String(e));
    } finally { setSaving(false); }
  };
  return <Spin spinning={loading}><Space direction="vertical" style={{ width: '100%', maxWidth: 850 }}>
    <Alert showIcon type="info" message={label('接入 LDAP / Active Directory', 'Connect LDAP / Active Directory')}
      description={label(
        '1. 在目录中创建只读搜索账号。2. 填写 LDAPS 地址，或启用 StartTLS 的 LDAP 地址；使用 DNS 名称匹配证书。3. 指定搜索根、精确过滤器和不可变用户 ID 属性。4. 保存后用测试成员在登录页选择“LDAP / AD 登录”；先从只读角色开始。',
        '1. Create a read-only directory search account. 2. Use an LDAPS URL, or LDAP with StartTLS, and a DNS name matching the certificate. 3. Set the search base, exact filter and immutable ID attribute. 4. Save, then sign in with a test member using LDAP / AD on the login page; start with the viewer role.')} />
    {error && <Alert showIcon type="error" message={error} description={conflict
      ? label('草稿仍在表单里；复制需要保留的修改再加载最新配置。', 'Your draft remains in the form. Copy any changes you need before reloading.') : undefined} />}
    {conflict && <Popconfirm title={label('丢弃草稿并加载最新配置？', 'Discard draft and load latest settings?')}
      onConfirm={async () => {
        try {
          const { data } = await ssoApi.ldapSettings();
          form.setFieldsValue({ ...data, bindPassword: undefined });
          revision.current = data.revision; setConfigured(data.credentialConfigured);
          setConflict(false); setError('');
        } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
      }}><Button>{label('加载最新配置', 'Reload settings')}</Button></Popconfirm>}
    <Form form={form} layout="vertical" disabled={loading || saving || !canWrite}
      onFinish={(values) => void save(values)}>
      <Form.Item name="enabled" label={label('启用目录登录', 'Enable directory sign-in')} valuePropName="checked"><Switch /></Form.Item>
      <Form.Item name="name" label={label('目录名称', 'Directory name')} rules={[{ required: true }]}>
        <Input maxLength={128} placeholder={label('公司 Active Directory', 'Company Active Directory')} />
      </Form.Item>
      <Form.Item name={['config', 'url']} label={label('目录服务器地址', 'Directory server URL')} rules={[{ required: true }]}
        extra={label('生产使用 ldaps://ad.example.com:636；也可使用 ldap://ad.example.com:389 并开启 StartTLS。始终校验证书。',
          'Use ldaps://ad.example.com:636, or ldap://ad.example.com:389 with StartTLS. Certificates are always verified.')}>
        <Input placeholder="ldaps://ad.example.com:636" />
      </Form.Item>
      <Form.Item name={['config', 'startTls']} label="StartTLS" valuePropName="checked"><Switch /></Form.Item>
      <Form.Item name={['config', 'caPem']} label={label('私有 CA 证书 PEM（可选）', 'Private CA certificate PEM (optional)')}
        extra={label('使用系统信任根时留空。仅粘贴签发目录服务器证书的 CA，不要粘贴私钥。',
          'Leave blank for system trust roots. Paste only the CA that issued the directory server certificate, never a private key.')}>
        <Input.TextArea rows={4} placeholder="-----BEGIN CERTIFICATE-----" />
      </Form.Item>
      <Form.Item name={['config', 'baseDn']} label={label('用户搜索根 DN', 'User search base DN')} rules={[{ required: true }]}>
        <Input placeholder="ou=People,dc=example,dc=com" />
      </Form.Item>
      <Form.Item name={['config', 'bindDn']} label={label('只读服务账号 DN', 'Read-only service account DN')} rules={[{ required: true }]}>
        <Input placeholder="cn=agf-reader,ou=Service,dc=example,dc=com" autoComplete="off" />
      </Form.Item>
      <Form.Item name="bindPassword" label={label('服务账号口令', 'Service account password')}
        extra={configured ? label('已加密保存；留空保留。更换地址或服务账号 DN 后必须重新填写。',
          'Encrypted and saved; leave blank to retain. Re-enter after changing the URL or bind DN.')
          : label('启用时必填；不会显示在配置读取结果中。', 'Required when enabled; never returned by settings read.')}>
        <Input.Password autoComplete="new-password" />
      </Form.Item>
      <Form.Item name={['config', 'userFilter']} label={label('用户过滤器', 'User filter')} rules={[{ required: true }]}
        extra={label('必须且只能包含一次 {username}；平台会转义输入，匹配多个账号时拒绝登录。',
          'Include {username} exactly once. Input is escaped and ambiguous matches are rejected.')}>
        <Input placeholder="(&(objectClass=user)(sAMAccountName={username}))" />
      </Form.Item>
      <Form.Item name={['config', 'idAttribute']} label={label('不可变用户 ID 属性', 'Immutable user ID attribute')}
        rules={[{ required: true }]} extra={label('AD 用 objectGUID；OpenLDAP 通常用 entryUUID。更换后原账号不会自动合并。',
          'Use objectGUID for AD or entryUUID for OpenLDAP. Changing this will not merge existing accounts.')}>
        <Input placeholder="objectGUID" />
      </Form.Item>
      <Form.Item name={['config', 'emailAttribute']} label={label('邮箱属性', 'Email attribute')}><Input placeholder="mail" /></Form.Item>
      <Form.Item name={['config', 'nameAttribute']} label={label('显示名属性', 'Display name attribute')}><Input placeholder="displayName" /></Form.Item>
      <Form.Item name="autoProvision" label={label('首次目录登录自动创建账号', 'Create account on first directory sign-in')}
        valuePropName="checked" extra={label('以目录地址和不可变 ID 绑定，不按邮箱合并本地管理员；关闭后只允许已纳管账号。',
          'Bind by directory URL and immutable ID; never merge local administrators by email. When off, only managed accounts can sign in.')}>
        <Switch />
      </Form.Item>
      <Form.Item name="defaultRole" label={label('新账号默认角色', 'Default role for new accounts')}>
        <Select options={[{ value: 'viewer', label: label('只读用户（推荐）', 'Viewer (recommended)') },
          { value: 'auditor', label: label('审计员', 'Auditor') },
          { value: 'soc-analyst', label: label('安全分析员', 'Security analyst') },
          { value: 'asset-owner', label: label('资产负责人', 'Asset owner') }]} />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={saving} disabled={!canWrite || conflict}>
        {label('保存目录配置', 'Save directory settings')}
      </Button>
    </Form>
    <Typography.Paragraph type="secondary">{label('目录密码不存入本平台。平台 MFA 仍会生效；禁用账号会阻止后续登录。',
      'Directory passwords are never stored by this platform. Platform MFA still applies; disabled accounts cannot sign in.')}</Typography.Paragraph>
  </Space></Spin>;
}
