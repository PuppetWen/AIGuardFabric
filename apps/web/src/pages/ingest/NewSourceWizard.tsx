import { useEffect, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Descriptions, Drawer, Form, Input, InputNumber, Select, Space, Switch } from 'antd';
import type { FormInstance } from 'antd';
import { NATIVE_RECEIVERS, sourceTransportControls } from './nativeSourceConfig';
import { SourceTransportFields } from './SourceTransportFields';
import { logSourcesApi } from '@/api/logSources';
import type { LogSource, Parser } from '@/types/domain';
import type { NewSourceValues } from './ingest.data';

interface Props {
  open: boolean; form: FormInstance<NewSourceValues>; step: number;
  setStep: Dispatch<SetStateAction<number>>; parsers: Parser[]; editing?: LogSource;
  onClose: () => void; onResetForm: () => void; onRefetch: () => void;
  onParserSearch?: (query: string) => void; parserLoading?: boolean;
}

/** Guided registration; fields from previous steps remain available when submitting. */
export function NewSourceWizard({ open, form, step, setStep, parsers, editing, onClose, onResetForm, onRefetch, onParserSearch, parserLoading }: Props) {
  const zh = !(useTranslation().i18n.language?.startsWith('en') ?? false);
  const text = (cn: string, en: string) => zh ? cn : en;
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  // Step changes render the next form section; read preserved values even after a field unmounts.
  const protocol = Form.useWatch('protocol', { form, preserve: true }) ?? 'http-webhook';
  const receiver = Form.useWatch('nativeReceiver', { form, preserve: true }) ?? '';
  useEffect(() => {
    if (!open) return;
    form.setFieldsValue(editing ? {
      name: editing.name, protocol: editing.nativeReceiver ? 'native' : editing.protocol, endpoint: editing.endpoint, nativeReceiver: editing.nativeReceiver,
      parserId: editing.parserId || undefined, pollIntervalSecs: editing.pollIntervalSecs ?? 60,
      enabled: editing.enabled, headersText: '',
      allowedCidrsText: editing.allowedCidrs?.join('\n') ?? '', requireMtls: editing.requireMtls ?? false,
    } : { nativeReceiver: undefined, protocol: 'http-webhook', pollIntervalSecs: 60, enabled: true, headersText: '', allowedCidrsText: '', requireMtls: false });
  }, [open, editing, form]);
  const save = async () => {
    setError(''); setSaving(true);
    try {
      await form.validateFields();
      const values = form.getFieldsValue(true);
      let headers: Record<string, string> | undefined;
      if (values.headersText?.trim()) {
        const parsed: unknown = JSON.parse(values.headersText);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
          || !Object.values(parsed).every((value) => typeof value === 'string')) {
          throw new Error(text('请求头必须是字符串键值组成的 JSON 对象',
            'Headers must be a JSON object with string keys and values'));
        }
        headers = parsed as Record<string, string>;
      }
      await logSourcesApi.save({
        name: values.name, protocol: values.protocol,
        nativeReceiver: values.protocol === 'native' ? values.nativeReceiver : undefined,
        endpoint: values.protocol === 'http-pull' ? values.endpoint : undefined,
        parserId: values.parserId || undefined, enabled: values.enabled,
        pollIntervalSecs: values.pollIntervalSecs, headers,
        ...(values.protocol === 'native' ? {
          allowedCidrs: sourceTransportControls(values.nativeReceiver ?? '').cidrs
            ? (values.allowedCidrsText ?? '').split(/\r?\n/).map((value: string) => value.trim()).filter(Boolean) : [],
          requireMtls: sourceTransportControls(values.nativeReceiver ?? '').mtls && !!values.requireMtls,
        } : {}),
      }, editing?.id);
      onRefetch(); onClose(); onResetForm();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : text('请检查必填项后重试', 'Check required fields and retry'));
    } finally { setSaving(false); }
  };
  return <Drawer width={660} open={open} onClose={saving ? undefined : onClose}
    title={editing ? text('编辑日志源', 'Edit log source') : text('接入日志源', 'Connect log source')} destroyOnClose
    extra={step === 2 ? <Button type="primary" loading={saving} onClick={() => void save()}>
      {text('保存并接入', 'Save and connect')}</Button> : undefined}>
    <Space direction="vertical" style={{ width: '100%' }} size={16}>
      {error && <Alert type="error" showIcon message={error} />}
      <Form form={form} layout="vertical" preserve>
        {step === 0 && <>
          <Form.Item name="protocol" label={text('接入方式', 'Connection method')} rules={[{ required: true }]}>
            <Select disabled={!!editing} options={[
              { value: 'http-webhook', label: text('HTTP Webhook · 平台或采集器主动推送', 'HTTP Webhook · sender pushes events') },
              { value: 'http-pull', label: text('HTTP Pull · 定时拉取平台日志 API', 'HTTP Pull · poll an upstream log API') },
              { value: 'native', label: text('原生接收器 · Syslog / Kafka / OTLP / MQTT 等', 'Native receiver · Syslog, Kafka, OTLP, MQTT and more') },
            ]} />
          </Form.Item>
          {protocol === 'native' && <Form.Item name="nativeReceiver" label={text('接收器', 'Receiver')} rules={[{ required: true }]}>
            <Select disabled={!!editing} showSearch options={NATIVE_RECEIVERS.map((value) => ({ value, label: value }))} />
          </Form.Item>}
          <Alert type="info" showIcon message={text('选择数据流向', 'Choose the event flow')}
            description={text('推送模式保存后生成专属地址，使用本租户具备 sources:write 权限的 API Key；拉取模式填写上游日志地址和认证请求头。原生模式生成独立接收器的租户与源绑定配置，并在接入指南中说明实际部署步骤。',
              'Push generates a dedicated URL and uses this tenant’s sources:write API key. Pull needs an upstream log URL and authentication headers. Native mode generates a tenant/source binding for a separate receiver; its connection guide explains deployment.')} />
        </>}
        {step === 1 && <>
          <Form.Item name="name" label={text('日志源名称', 'Source name')} rules={[{ required: true, whitespace: true }]}>
            <Input maxLength={200} placeholder={text('例如：生产模型网关审计', 'Example: production model gateway audit')} />
          </Form.Item>
          {protocol === 'http-pull' ? <>
            <Form.Item name="endpoint" label={text('上游日志 API 地址', 'Upstream log API URL')} rules={[{ required: true }]}>
              <Input placeholder="https://logs.example.com/api/events" />
            </Form.Item>
            <Form.Item name="pollIntervalSecs" label={text('拉取间隔（秒）', 'Pull interval (seconds)')} rules={[{ required: true }]}>
              <InputNumber min={5} max={86400} />
            </Form.Item>
            <Form.Item name="headersText" label={text('认证请求头（JSON，可选）', 'Authentication headers (optional JSON)')}
              extra={editing?.headersConfigured
                ? text('已有凭据。留空保留，输入 {} 清除。修改地址时必须重新填写凭据。',
                  'A credential is saved. Leave blank to keep it or enter {} to clear it. Re-enter credentials if the URL changes.')
                : text('保存后加密，不回显。支持 Authorization 等请求头。',
                  'Encrypted after saving and never displayed again. Authorization and other headers are supported.')}>
              <Input.TextArea rows={3} autoComplete="off" placeholder={'{"Authorization":"Bearer YOUR_UPSTREAM_TOKEN"}'} />
            </Form.Item>
          </> : <Alert type="info" message={protocol === 'native'
            ? text('保存后打开“接入指南”复制部署配置，绑定到当前租户的接收器。',
              'After saving, open Connection guide and copy the receiver configuration for this tenant.')
            : text('平台会自动生成推送地址，无需填写监听端口。保存后点击“接入指南”复制命令。',
              'The platform creates a push URL automatically. No listener port is needed; open Connection guide after saving.')} />}
          <Form.Item name="enabled" label={text('启用日志源', 'Enable source')} valuePropName="checked"><Switch /></Form.Item>
          {protocol === 'native' && <SourceTransportFields receiver={receiver} />}
        </>}
        {step === 2 && <>
          <Form.Item name="parserId" label={text('解析模板（留空自动匹配）', 'Parser (blank for automatic matching)')}
            extra={text('AI 工具事件要关联资产、生成发现，请选择映射 message、severity、category、mcp 字段的 JSONPath 模板；未命中模板只会保存原文。',
              'For AI tool events and asset-linked findings, select a JSONPath parser mapping message, severity, category and mcp. Without a match, only the raw record is saved.')}>
            <Select allowClear showSearch optionFilterProp="label" placeholder={text('自动匹配已加载模板', 'Match loaded parsers automatically')}
              onSearch={onParserSearch} filterOption={!onParserSearch} loading={parserLoading}
              options={parsers.map((parser) => ({ value: parser.id, label: parser.name }))} />
          </Form.Item>
          <Descriptions bordered column={1} size="small">
            <Descriptions.Item label={text('日志源', 'Source')}>{form.getFieldValue('name')}</Descriptions.Item>
            <Descriptions.Item label={text('接入方式', 'Connection method')}>{protocol}</Descriptions.Item>
            {protocol === 'native' && sourceTransportControls(receiver).cidrs && <Descriptions.Item label={text('来源限制', 'Source restrictions')}>
              {form.getFieldValue('allowedCidrsText') || text('所有来源', 'All sources')}
              {form.getFieldValue('requireMtls') && sourceTransportControls(receiver).mtls ? ' · mTLS' : ''}
            </Descriptions.Item>}
            <Descriptions.Item label={text('地址', 'Endpoint')}>{protocol === 'native' ? form.getFieldValue('nativeReceiver') : protocol === 'http-pull' ? form.getFieldValue('endpoint') : text('保存后生成专属推送地址', 'Dedicated push URL after saving')}</Descriptions.Item>
          </Descriptions>
          <Alert style={{ marginTop: 12 }} type="info" message={text('完成后的验证方法', 'How to verify')}
            description={text('推送源打开“接入指南”；拉取源点击“立即拉取”。查看已保存条数、解析命中数和最近错误。未命中的原文会保留，后续可重新解析。',
              'For push, open Connection guide; for pull, use Pull now. Check saved and parsed counts and the latest error. Unmatched raw records remain available for replay.')} />
        </>}
      </Form>
      <Space>
        <Button disabled={step === 0 || saving} onClick={() => setStep((value) => value - 1)}>{text('上一步', 'Previous')}</Button>
        {step < 2 && <Button type="primary" onClick={() => {
          void form.validateFields(step === 0 ? (protocol === 'native' ? ['protocol', 'nativeReceiver'] : ['protocol']) : protocol === 'http-pull'
            ? ['name', 'endpoint', 'pollIntervalSecs'] : ['name']).then(() => {
              setError(''); setStep((value) => value + 1);
            }).catch(() => undefined);
        }}>{text('下一步', 'Next')}</Button>}
      </Space>
    </Space>
  </Drawer>;
}
