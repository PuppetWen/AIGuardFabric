import { useState } from 'react';
import { Alert, Button, Checkbox, Descriptions, Input, Space, Typography } from 'antd';
import type { ConfigurationObservation as Observation, ConfigurationState } from '@/types/apigConfigurationPublication';
import { matching } from './eligibility';
import { useApigText } from './text';

export default function ConfigurationObservation({ data, baseline, busy, canWrite, onObserve, onAdopt }: {
  data: ConfigurationState; baseline: Observation | null; busy: boolean; canWrite: boolean;
  onObserve: (live: boolean, initialize: boolean) => void; onAdopt: () => void;
}) {
  const text = useApigText(), [live, setLive] = useState(false), [initialize, setInitialize] = useState(false), target = data.binding;
  return <Space direction="vertical" style={{ width: '100%' }}>
    {target ? <Descriptions size="small" column={2} bordered items={[
      { key: 'source', label: text('实际来源', 'Actual source'), children: target.sourceLabel },
      { key: 'mode', label: text('实际模式 / 地域', 'Effective mode / region'), children: `${target.transportMode} / ${target.region}` },
      { key: 'scope', label: 'Scope / configuration', children: `${target.targetScopeId} / v${target.configurationVersion}` },
      { key: 'kind', label: text('既有受管对象', 'Existing managed object'), children: target.binding.kind },
    ]} /> : <Alert type="warning" message={data.bindingReason ?? text('尚未配置可信目标', 'No trusted target is configured')} />}
    <Alert type="info" message={text('GET 只读本地状态；明确观察才读取已安装挂载或已有 Model API。',
      'GET reads local state only. Explicit observation reads the installed attachment or existing Model API.')}
      description={text('观察与回读不证明部署或消费者加载；云无 CAS。观察成功后，仍须明确采用才替换草稿基线。',
        'Observation and readback do not prove deployment or consumer loading; there is no cloud CAS. Explicit adoption is required to replace the draft baseline.')} />
    {target?.transportMode === 'live' && <Checkbox checked={live} disabled={busy} onChange={e => setLive(e.target.checked)}>
      {text('确认对上述 Live 目标执行只读观察', 'Confirm read-only observation of the Live target above')}</Checkbox>}
    {data.canInitializeMockFixture && <Checkbox checked={initialize} disabled={busy || !canWrite} onChange={e => setInitialize(e.target.checked)}>
      {text('明确初始化此绑定的受控 Mock 示例（不创建实云资源）', 'Explicitly initialize the owned Mock example for this binding (no live resources)')}</Checkbox>}
    <Button disabled={busy || data.busy || !data.canObserve || (target?.transportMode === 'live' && !live)} onClick={() => onObserve(live, initialize)}>
      {text('明确观察 APIG 配置目标', 'Explicitly observe the APIG configuration target')}</Button>
    {data.observation && <>
      <Typography.Text>{text('最新观察', 'Latest observation')}: {data.observation.id} / {data.observation.observedAt}</Typography.Text>
      <Typography.Text>{text('指纹 / 内容 hash', 'Fingerprint / content hash')}: {data.observation.fingerprint} / {data.observation.contentHash}</Typography.Text>
      {data.observation.reason && <Alert type="warning" message={data.observation.reason} />}
      <Input.TextArea readOnly rows={5} aria-label={text('观察到的公开配置', 'Observed public configuration')} value={JSON.stringify(data.observation.view, null, 2)} />
      <Button disabled={busy || !matching(data, data.observation)} onClick={onAdopt}>{text('明确采用最新配置观察', 'Explicitly adopt the latest configuration observation')}</Button>
    </>}
    <Typography.Text>{text('草稿仍采用观察', 'Draft still uses observation')}: {baseline?.id ?? '—'}</Typography.Text>
  </Space>;
}
