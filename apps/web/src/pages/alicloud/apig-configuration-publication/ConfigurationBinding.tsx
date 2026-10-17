import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Checkbox, Input, Popconfirm, Space, Spin, Typography, Radio } from 'antd';
import { cloudApi, type CloudConfig } from '@/api/cloud';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { bindingBody, bindingDraft, contentFields, commonFields, mockExample, type BindingDraft, type BindingField } from './binding';
import { failure, useApigText } from './text';

const names: Record<BindingField,string> = {configuration_http_api_id:'Model API ID', configuration_gateway_id:'Gateway ID', configuration_environment_id:'Environment ID',
 configuration_attachment_id:'Plugin attachment ID', configuration_plugin_id:'Installed plugin ID', configuration_class_id:'Actual plugin class ID', configuration_class_version:'Actual plugin class version'};
export default function ConfigurationBinding({ onSaved }: { onSaved: () => void }) {
  const text = useApigText(), scope = useOperationScope(), sequence = useRef(0), comparison = useRef<AbortController | null>(null);
  const [config, setConfig] = useState<CloudConfig | null>(null), [draft, setDraft] = useState<BindingDraft | null>(null);
  const [latest, setLatest] = useState<CloudConfig | null>(null), [busy, setBusy] = useState(false), [reading, setReading] = useState(false), [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController(), id = ++sequence.current;
    void cloudApi.configuration('alicloud-apig', controller.signal).then(response => {
      if (!controller.signal.aborted && scope.current() && id === sequence.current) { setConfig(response.data); setDraft(bindingDraft(response.data)); }
    }).catch(cause => { if (!controller.signal.aborted && scope.current() && id === sequence.current) setError(failure(cause)); });
    return () => { controller.abort(); comparison.current?.abort(); };
  }, [scope]);
  const update = (patch: Partial<BindingDraft>) => { if (!busy && scope.current()) setDraft(old => old && { ...old, ...patch, confirmed: false }); };
  const compare = async () => {
    if (busy || reading || !scope.current()) return;
    const id = ++sequence.current, controller = new AbortController(); comparison.current?.abort(); comparison.current = controller; setReading(true);
    try { const response = await cloudApi.configuration('alicloud-apig', controller.signal); if (!controller.signal.aborted && scope.current() && id === sequence.current) setLatest(response.data); }
    catch (cause) { if (!controller.signal.aborted && scope.current() && id === sequence.current) setError(failure(cause)); }
    finally { if (!controller.signal.aborted && scope.current() && id === sequence.current) setReading(false); }
  };
  const save = async () => {
    if (!config || !draft) return;
    const generation = scope.begin(); if (generation === undefined) return;
    setBusy(true); setError('');
    try {
      const body = bindingBody(config, draft);
      if (!scope.current(generation)) return;
      const response = await cloudApi.save('alicloud-apig', body);
      if (scope.current(generation)) { setConfig(response.data); setDraft(bindingDraft(response.data)); setLatest(null); onSaved(); }
    } catch (cause) { if (scope.current(generation)) setError(failure(cause)); }
    finally { if (scope.finish(generation)) setBusy(false); }
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Alert type="info" message={text('只绑定已安装的内容安全挂载或已有 Model API 部署。保存不安装插件、不创建资源、不初始化 Mock 或发送云配置。',
      'Bind an installed content-security attachment or existing Model API deployment. Saving does not install plugins, create resources, initialize Mock or send cloud configuration.')}
      description={text('账号、服务 endpoint 与凭据仍在“连接配置”维护。目标、模式、来源或凭据变化会清除旧管理确认；返回此处核对后重新明确确认。',
        'Maintain account, service endpoint and credentials in Connection configuration. Target, mode, source or credential changes clear prior management consent; verify and reconfirm here.')} />
    {error && <Alert type="error" message={error} description={text('401/409 保留草稿和保存版本。先读取最新配置比较，再明确采用；不会自动重发。',
      'HTTP 401/409 preserves the draft and save revision. Read the latest configuration to compare, then adopt explicitly; no automatic retry.')} />}
    {!config || !draft ? !error && <Spin /> : <>
      <Typography.Text>{text('保存使用配置版本', 'Save uses configuration version')} {config.version}</Typography.Text>
      <Checkbox checked={draft.enabled} disabled={busy} onChange={event => update({ enabled: event.target.checked })}>{text('启用 APIG 配置连接', 'Enable APIG configuration connection')}</Checkbox>
      <Checkbox checked={draft.mock} disabled={busy} onChange={event => update({ mock: event.target.checked })}>{text('配置 Mock 模式', 'Configure Mock mode')}</Checkbox>
      {config.environmentMock && <Alert type="warning" message={text('服务端全局 Mock 开启；实际模式以服务端绑定为准。', 'Server Mock mode is enabled; use the effective server binding mode.')} />}
      <Radio.Group aria-label={text('受管配置类型', 'Managed configuration kind')} value={draft.kind} disabled={busy}
 onChange={event => update({kind:event.target.value})} options={[{label:text('内容安全已安装挂载', 'Installed content-security attachment'),value:'content'}, {label:text('既有模型配置', 'Existing model configuration'),value:'models'}]} />
 <Input aria-label={text('APIG 目标地域', 'APIG target region')} value={draft.region} disabled={busy} onChange={event => update({ region: event.target.value })} />
      {(draft.kind === 'content' ? [...commonFields, ...contentFields] : [...commonFields]).map(key => <Input key={key} aria-label={names[key]} addonBefore={names[key]} value={draft.ids[key]} disabled={busy}
        onChange={event => update({ ids: { ...draft.ids, [key]: event.target.value } })} />)}
      <Button disabled={busy || !draft.kind || !(draft.mock || config.environmentMock)} onClick={() => { if (scope.current()) setDraft(mockExample(draft)); }}>
        {text('明确填入当前类型的受控 Mock 示例（不保存）', 'Explicitly fill the owned Mock example for this kind (no save)')}</Button>
      <Typography.Text type="secondary">{text('示例不是实云资源；只在实际 Mock 模式可用。填入后仍需人工确认、保存，再明确观察并勾选初始化。',
        'The example is not a live-cloud resource and is available only in Mock mode. Confirm and save manually, then explicitly observe with initialization consent.')}</Typography.Text>
      <Checkbox checked={draft.confirmed} disabled={busy} onChange={event => { if (scope.current()) setDraft({ ...draft, confirmed: event.target.checked }); }}>
        {text('确认仅管理公开字段，保留私密配置；流式及其它资源共享影响未知', 'Confirm public-field management, preserving private configuration; streaming and shared-resource impact remain unknown')}</Checkbox>
      <Space><Button loading={busy} disabled={!draft.confirmed || reading} onClick={() => void save()}>{text('保存 APIG 配置绑定', 'Save APIG configuration binding')}</Button>
        <Button disabled={busy} loading={reading} onClick={() => void compare()}>{text('读取最新 APIG 配置比较（GET）', 'Read latest APIG configuration to compare (GET)')}</Button></Space>
      {latest && <>
        <Typography.Text>{text('当前草稿 / 最新配置版本', 'Draft / latest configuration revision')}: {config.version} / {latest.version}</Typography.Text>
        <Input.TextArea readOnly rows={5} aria-label={text('最新 APIG 绑定比较', 'Latest APIG binding comparison')}
          value={JSON.stringify(bindingDraft(latest), null, 2)} />
        <Popconfirm title={text('明确替换绑定草稿和保存版本？', 'Explicitly replace the binding draft and save revision?')}
          okText={text('确认采用最新绑定', 'Confirm adopting latest binding')} onConfirm={() => {
            if (!busy && scope.current()) { setConfig(latest); setDraft(bindingDraft(latest)); setLatest(null); setError(''); }
          }}><Button disabled={busy}>{text('明确采用最新 APIG 绑定', 'Explicitly adopt latest APIG binding')}</Button></Popconfirm>
      </>}
    </>}
  </Space>;
}
