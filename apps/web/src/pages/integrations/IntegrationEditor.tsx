import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Drawer, Form, Input, InputNumber, Select, Space, Spin, Switch, Tabs, Typography } from 'antd';
import { integrationsApi, type IntegrationConfig, type Probe } from '@/api/integrations';
import { settingFields } from './fields';
import IntegrationOperations from './IntegrationOperations';
import { IntegrationGuide } from './IntegrationGuide';

export default function IntegrationEditor({ name, title, onClose, onSaved }: {
  name: string; title: string; onClose: () => void; onSaved: () => void;
}) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const [snapshot, setSnapshot] = useState<IntegrationConfig>();
  const [error, setError] = useState('');
  useEffect(() => {
    let live = true;
    void integrationsApi.configuration(name).then((result) => { if (live) setSnapshot(result.data); })
      .catch((cause) => { if (live) setError(String(cause)); });
    return () => { live = false; };
  }, [name]);
  return <Drawer open width={720} title={title} onClose={onClose} destroyOnClose>
    {error ? <Alert type="error" message={error} /> : !snapshot ? <Spin /> :
      <Tabs items={[
        { key: 'configuration', label: zh ? '配置' : 'Configuration', children: <EditorForm key={snapshot.version} snapshot={snapshot} onSaved={(value) => { setSnapshot(value); onSaved(); }} /> },
        { key: 'operations', label: zh ? '业务调用与记录' : 'Operations and history', children: <IntegrationOperations key={snapshot.version} snapshot={snapshot} /> },
        { key: 'guide', label: zh ? '接入指南' : 'Guide', children: <IntegrationGuide /> },
      ]} />}
  </Drawer>;
}

function EditorForm({ snapshot, onSaved }: {snapshot: IntegrationConfig; onSaved: (value: IntegrationConfig) => void}) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [form] = Form.useForm();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [dirty, setDirty] = useState(false);
  const [probe, setProbe] = useState<Probe | null>(snapshot.probe);
  const keys = [...new Set([...snapshot.metadata.requiredSecrets, ...snapshot.metadata.optionalSecrets])];
  const initialSettings = JSON.parse(snapshot.settingsJson) as Record<string, unknown>;
  const endpointKey = snapshot.metadata.endpointKey;
  const fields = settingFields[snapshot.name] ?? [];
  const friendly = Object.fromEntries(fields.map(field => [field.key,
    Array.isArray(initialSettings[field.key]) ? (initialSettings[field.key] as string[]).join(',') : initialSettings[field.key]]));
  fields.forEach(field => { delete initialSettings[field.key]; });
  const endpoint = endpointKey ? initialSettings[endpointKey] : undefined;
  if (endpointKey) delete initialSettings[endpointKey];
  const save = async () => {
    setBusy(true); setError('');
    try {
      const values = await form.validateFields();
      const settings: unknown = JSON.parse(values.settings);
      if (!settings || Array.isArray(settings) || typeof settings !== 'object') throw new Error(text('设置必须是 JSON 对象', 'Settings must be a JSON object'));
      if (endpointKey && values.endpoint) (settings as Record<string, unknown>)[endpointKey] = values.endpoint;
      for (const field of fields) {
        const value = values.friendly?.[field.key];
        if (value !== undefined && value !== null && value !== '') (settings as Record<string, unknown>)[field.key] = value;
      }
      const result = await integrationsApi.save(snapshot.name, {
        settings, secrets: values.secrets ?? {}, enabled: values.enabled, mock: values.mock,
        clear_secrets: values.clear ?? [], expected_version: snapshot.version,
      });
      onSaved(result.data);
    } catch (cause) { if (cause instanceof Error) setError(cause.message); }
    finally { setBusy(false); }
  };
  return <Space direction="vertical" style={{ width: '100%' }} size="middle">
    <Alert type="info" showIcon message={text('配置加密保存，凭据不回显', 'Configuration is encrypted; saved secrets are never returned')}
      description={text('修改地址时需重新输入凭据。留空保留已有值；勾选清除会移除所选凭据。仅检查连接不会发送消息或操作设备。',
        'Re-enter credentials when changing an endpoint. Empty fields preserve saved secrets; selected clear fields remove them. Connection checks do not send messages or control devices.')} />
    {snapshot.environmentMock && <Alert type="warning" message={text('服务处于模拟模式：所有探测和业务调用均不触达外部系统', 'Server mock mode is active: probes and adapter calls do not contact external systems')} />}
    <Form form={form} layout="vertical" onValuesChange={() => { setDirty(true); setProbe(null); }} initialValues={{
      enabled: snapshot.enabled, mock: snapshot.mock, endpoint, friendly, settings: JSON.stringify(initialSettings, null, 2),
    }}>
      <Space size="large"><Form.Item name="enabled" label={text('启用', 'Enabled')} valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name="mock" label={text('此集成使用模拟模式', 'Mock this integration')} valuePropName="checked"><Switch /></Form.Item></Space>
      {endpointKey && <Form.Item name="endpoint" label={text('服务地址', 'Service endpoint')}><Input placeholder="https://service.example.com" autoComplete="off" /></Form.Item>}
      {fields.map(field => <Form.Item key={field.key} name={['friendly', field.key]} label={text(field.zh, field.en)}>
        {field.choices ? <Select allowClear options={field.choices.map(value => ({ value }))} /> : field.number
          ? <InputNumber min={0} placeholder={field.placeholder} style={{ width: '100%' }} /> : <Input placeholder={field.placeholder} autoComplete="off" />}
      </Form.Item>)}
      {keys.map((key) => <Form.Item key={key} name={['secrets', key]} label={key}
        extra={snapshot.secretKeys.includes(key) ? text('已保存；留空保留', 'Saved; leave blank to preserve') : snapshot.metadata.requiredSecrets.includes(key) ? text('启用真实模式时必填', 'Required for live mode') : text('可选', 'Optional')}>
        <Input.Password autoComplete="new-password" />
      </Form.Item>)}
      {!!snapshot.secretKeys.length && <Form.Item name="clear" label={text('清除已保存凭据', 'Remove saved credentials')}><Checkbox.Group options={snapshot.secretKeys} /></Form.Item>}
      <Form.Item name="settings" label={text('其他设置 JSON', 'Additional settings JSON')} rules={[{ required: true }]}>
        <Input.TextArea rows={8} spellCheck={false} />
      </Form.Item>
    </Form>
    <Typography.Paragraph type="secondary">{snapshot.metadata.degradation}</Typography.Paragraph>
    <Typography.Text type="secondary">{text('已保存配置版本', 'Saved configuration version')}: {snapshot.version}</Typography.Text>
    <Space><Button type="primary" loading={busy} onClick={() => void save()}>{text('保存配置', 'Save configuration')}</Button>
      <Button disabled={dirty || !snapshot.enabled || busy} onClick={async () => {
        setBusy(true); setError(''); try { setProbe((await integrationsApi.probe(snapshot.name)).data); }
        catch (cause) { setError(String(cause)); } finally { setBusy(false); }
      }}>{text('检查 TCP 连通性', 'Check TCP reachability')}</Button></Space>
    {dirty && <Typography.Text type="secondary">{text('请先保存修改，再检查连接', 'Save changes before checking connectivity')}</Typography.Text>}
    {error && <Alert type="error" message={error} />}
    {probe && <Alert type={probe.tcpReachable === false ? 'error' : 'info'} showIcon message={probe.note}
      description={<>{probe.host && <span>{probe.host}:{probe.port} · </span>}{probe.checkedAt}</>} />}
  </Space>;
}
