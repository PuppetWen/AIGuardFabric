import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Form, Input, Popconfirm, Select, Space, Spin, Switch, Typography, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { ssoApi, type OidcSettings } from '@/api/sso';
import { ApiRequestError } from '@/api/transport';
import { identityText } from './identityText';

export function IdentityTab({ canWrite }: { canWrite: boolean }) {
  const { i18n } = useTranslation();
  const words = identityText(i18n.language);
  const [form] = Form.useForm<OidcSettings>();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [conflict, setConflict] = useState(false);
  const [configured, setConfigured] = useState(false);
  const revision = useRef<string | null>(null);
  useEffect(() => {
    let active = true;
    void ssoApi.settings().then(({ data }) => {
      if (active) {
        form.setFieldsValue({ ...data, redirectUri: data.redirectUri || `${window.location.origin}/login/oidc/callback` });
        revision.current = data.revision;
        setConfigured(data.credentialConfigured);
      }
    }).catch((e: Error) => { if (active) setError(e.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [form]);
  const save = async (values: OidcSettings) => {
    if (!canWrite || conflict) return;
    setSaving(true); setError('');
    try {
      const { data } = await ssoApi.save(values, revision.current);
      form.setFieldsValue({ ...data, clientSecret: undefined });
      revision.current = data.revision;
      setConfigured(data.credentialConfigured);
      message.success(data.enabled ? words.saved : words.disabled);
    } catch (e) {
      setConflict(e instanceof ApiRequestError && e.status === 409);
      setError(e instanceof Error ? e.message : String(e));
    }
    finally { setSaving(false); }
  };
  return <Spin spinning={loading}><Space direction="vertical" style={{ width: '100%', maxWidth: 800 }}>
    <Alert type="info" showIcon message={words.introTitle} description={words.intro} />
    {error && <Alert type="error" showIcon message={error}
      description={conflict ? words.draft : undefined} />}
    {conflict && <Popconfirm title={words.discard}
      onConfirm={async () => {
        try {
          const { data } = await ssoApi.settings();
          form.setFieldsValue({ ...data, clientSecret: undefined,
            redirectUri: data.redirectUri || `${window.location.origin}/login/oidc/callback` });
          revision.current = data.revision;
          setConfigured(data.credentialConfigured);
          setConflict(false);
          setError('');
        } catch (failure) { setError(failure instanceof Error ? failure.message : String(failure)); }
      }}>
      <Button>{words.reload}</Button>
    </Popconfirm>}
    <Form form={form} layout="vertical" disabled={loading || saving || !canWrite} onFinish={(values) => void save(values)}>
      <Form.Item name="enabled" label={words.enabledLabel} valuePropName="checked"><Switch /></Form.Item>
      <Form.Item name="name" label={words.providerName} rules={[{ required: true }]}><Input maxLength={128} placeholder={words.providerExample} /></Form.Item>
      <Form.Item name="issuer" label="Issuer URL" rules={[{ required: true }, { type: 'url' }]}
        extra={words.issuerHelp}>
        <Input placeholder="https://id.example.com/realms/company" />
      </Form.Item>
      <Form.Item name="clientId" label="Client ID" rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
      <Form.Item name="clientAuth" label={words.clientAuth}><Select options={[
        { value: 'client_secret_basic', label: 'Client Secret Basic' }, { value: 'client_secret_post', label: 'Client Secret Post' },
        { value: 'none', label: words.publicClient },
      ]} /></Form.Item>
      <Form.Item name="clientSecret" label="Client Secret" extra={configured ? words.secretSaved : words.secretRequired}>
        <Input.Password autoComplete="new-password" placeholder={configured ? words.secretConfigured : words.secretPlaceholder} />
      </Form.Item>
      <Form.Item name="redirectUri" label={words.callback} rules={[{ required: true }, { type: 'url' }]}
        extra={words.callbackHelp}><Input /></Form.Item>
      <Form.Item name="autoProvision" label={words.autoProvision} valuePropName="checked"
        extra={words.autoProvisionHelp}><Switch /></Form.Item>
      <Form.Item name="defaultRole" label={words.defaultRole} extra={words.defaultRoleHelp}><Select options={[
        { value: 'viewer', label: words.viewer }, { value: 'auditor', label: words.auditor },
        { value: 'soc-analyst', label: words.analyst }, { value: 'asset-owner', label: words.owner },
      ]} /></Form.Item>
      <Form.Item name="emailDomains" label={words.domains} extra={words.domainsHelp}>
        <Select mode="tags" tokenSeparators={[',', ';', ' ']} placeholder="example.com" />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={saving} disabled={!canWrite || conflict}>{words.save}</Button>
    </Form>
    <Typography.Paragraph type="secondary">{words.footnote}</Typography.Paragraph>
  </Space></Spin>;
}
