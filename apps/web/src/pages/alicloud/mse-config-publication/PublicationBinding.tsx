import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Checkbox, Input, Popconfirm, Radio, Space, Spin, Typography } from 'antd';
import { cloudApi, type CloudConfig } from '@/api/cloud';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { bindingBody, bindingDraft, type BindingDraft } from './binding';
import { failure, usePublicationText } from './text';

export default function PublicationBinding({ onSaved }: { onSaved: () => void }) {
  const text = usePublicationText(), scope = useOperationScope(), sequence = useRef(0);
  const [config, setConfig] = useState<CloudConfig | null>(null), [draft, setDraft] = useState<BindingDraft | null>(null);
  const [latest, setLatest] = useState<CloudConfig | null>(null), [busy, setBusy] = useState(false), [reading, setReading] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController(), id = ++sequence.current;
    void cloudApi.configuration('alicloud-mse', controller.signal).then(response => {
      if (!controller.signal.aborted && scope.current() && id === sequence.current) {
        setConfig(response.data); setDraft(bindingDraft(response.data));
      }
    }).catch(cause => { if (!controller.signal.aborted && scope.current()) setError(cause instanceof Error ? cause.message : '配置加载失败 / Configuration loading failed'); });
    return () => controller.abort();
  }, [scope]);
  const update = (patch: Partial<BindingDraft>) => {
    if (!busy && scope.current()) setDraft(value => value && { ...value, ...patch, confirmed: false });
  };
  const compare = async () => {
    if (busy || reading || !scope.current()) return;
    const id = ++sequence.current; setReading(true);
    try {
      const response = await cloudApi.configuration('alicloud-mse');
      if (scope.current() && id === sequence.current) setLatest(response.data);
    } catch (cause) { if (scope.current() && id === sequence.current) setError(failure(cause, text)); }
    finally { if (scope.current() && id === sequence.current) setReading(false); }
  };
  const save = async () => {
    if (!config || !draft) return;
    const generation = scope.begin(); if (generation === undefined) return;
    setBusy(true); setError('');
    try {
      const captured = bindingBody(config, draft);
      if (!scope.current(generation)) return;
      const response = await cloudApi.save('alicloud-mse', captured);
      if (scope.current(generation)) { setConfig(response.data); setDraft(bindingDraft(response.data)); setLatest(null); onSaved(); }
    } catch (cause) { if (scope.current(generation)) setError(failure(cause, text)); }
    finally { if (scope.finish(generation)) setBusy(false); }
  };
  const adopt = () => {
    if (!latest || busy || !scope.current()) return;
    setConfig(latest); setDraft(bindingDraft(latest)); setLatest(null); setError('');
  };
  const fields: [keyof Pick<BindingDraft, 'origin' | 'region' | 'instance' | 'group' | 'dataId'>, string, string][] = [
    ['origin', 'Nacos 引擎 origin', 'Nacos engine origin'], ['region', '发布目标地域', 'Publication region'],
    ['instance', '发布目标实例 ID', 'Publication instance ID'], ['group', '配置 Group', 'Configuration group'], ['dataId', '专用 Data ID', 'Dedicated Data ID'],
  ];
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Alert type="info" showIcon message={text('此处配置独立 Nacos 引擎目标；旧 OpenAPI 地址保持独立，凭据需遵循目标变更规则。', 'Configure the separate Nacos engine target here; the OpenAPI address stays independent and credentials follow the target-change rules.')}
      description={text('凭据与来源身份请在原“连接配置”维护。真实启用连接更换 engine origin 时，先明确停用，或在连接配置同次保存新地址及适用凭据，再回此处重新确认。不会自动切换 Mock 或停用。保存不查询云或发布策略。', 'Maintain credentials and source identity in Connection configuration. For a new engine origin on an enabled Live connection, explicitly disable first or save the new origin and appropriate credentials together in Connection configuration, then return to reconfirm. No automatic Mock or disable switch occurs. Saving neither queries the cloud nor publishes policies.')} />
    {error && <Alert type="error" message={error} description={text('409 后草稿和原保存版本保留。先读取最新配置比较，再明确采用；不会自动重发。', 'After HTTP 409 the draft and original save version remain. Read the latest configuration to compare, then adopt explicitly; no automatic retry.')} />}
    {!draft || !config ? !error && <Spin /> : <>
      <Typography.Text>{text('保存使用配置版本', 'Save uses configuration version')} {config.version}</Typography.Text>
      <Checkbox checked={draft.enabled} disabled={busy} onChange={event => update({ enabled: event.target.checked })}>{text('启用发布连接', 'Enable publication connection')}</Checkbox>
      <Checkbox checked={draft.mock} disabled={busy} onChange={event => update({ mock: event.target.checked })}>{text('配置 Mock 模式', 'Configure Mock mode')}</Checkbox>
      {config.environmentMock && <Alert type="warning" message={text('服务端全局 Mock 已启用；实际模式由服务端绑定显示。', 'Server Mock mode is active; the server binding shows the effective mode.')} />}
      {fields.map(([key, cn, en]) => <label key={key}>{text(cn, en)}<Input aria-label={text(cn, en)} value={draft[key]} disabled={busy}
        onChange={event => update({ [key]: event.target.value })} /></label>)}
      <Typography.Text>{text('命名空间选择', 'Namespace selection')}</Typography.Text>
      <Radio.Group aria-label={text('发布命名空间', 'Publication namespace')} value={draft.namespaceMode} disabled={busy}
        onChange={event => update({ namespaceMode: event.target.value as 'default' | 'specific' })}>
        <Radio value="default">{text('默认 namespace（明确空字符串）', 'Default namespace (explicit empty string)')}</Radio>
        <Radio value="specific">{text('指定真实 namespace ID', 'Specify the actual namespace ID')}</Radio>
      </Radio.Group>
      {draft.namespaceMode === 'specific' && <Input aria-label="Publication namespace ID" value={draft.namespace} disabled={busy} onChange={event => update({ namespace: event.target.value })} />}
      <Typography.Text>nacos-http-v2-cas</Typography.Text>
      <Checkbox checked={draft.confirmed} disabled={busy} onChange={event => setDraft({ ...draft, confirmed: event.target.checked })}>
        {text('确认管理此专用 JSON Data ID：MD5 upsert 可能重建观察后被删除的配置', 'Confirm management of this dedicated JSON Data ID: MD5 upsert may recreate a configuration deleted after observation')}
      </Checkbox>
      <Space wrap><Button type="primary" loading={busy} disabled={!draft.confirmed} onClick={() => void save()}>{text('保存发布目标绑定', 'Save publication target binding')}</Button>
        <Button loading={reading} disabled={busy} onClick={() => void compare()}>{text('读取最新配置比较', 'Read latest configuration to compare')}</Button></Space>
      {latest && <><Typography.Text>{text('服务器配置版本', 'Server configuration version')} {latest.version}</Typography.Text>
        <Input.TextArea readOnly aria-label={text('最新发布绑定比较', 'Latest publication binding comparison')} value={JSON.stringify(bindingDraft(latest), null, 2)} rows={7} />
        <Popconfirm title={text('用最新配置替换草稿及保存版本？需重新确认 upsert。', 'Replace the draft and save version with the latest configuration? Reconfirm upsert.')}
          okText={text('明确采用最新配置', 'Confirm adopting latest configuration')} onConfirm={adopt}>
          <Button disabled={busy}>{text('采用最新配置', 'Adopt latest configuration')}</Button>
        </Popconfirm></>}
    </>}
  </Space>;
}
