import { useState } from 'react';
import { Button, Checkbox, Input, InputNumber, Select, Space } from 'antd';
import { payload } from './validation';
import type { Payload, Source } from './types';
export default function CmsQueueForm({ source, disabled, zh, onSubmit }: {
  source: Source | null; disabled: boolean; zh: boolean; onSubmit: (body: Payload, seed: boolean) => void;
}) {
  const text = (cn: string, en: string) => zh ? cn : en;
  const [kind, setKind] = useState<'event' | 'metric'>('event');
  const [name, setName] = useState(''); const [content, setContent] = useState('');
  const [value, setValue] = useState<number | null>(0); const [dimensions, setDimensions] = useState('{}');
  const [seedSource, setSeedSource] = useState<string>(); const [invalid, setInvalid] = useState(false);
  const sourceKey = source ? `${source.configurationId}:${source.configurationVersion}` : 'none';
  const seed = seedSource === sourceKey;
  const canSeed = source?.mocked && source.region === 'cn-hangzhou' && source.groupId === 'agf-cms-demo';
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Select aria-label={text('条目类型', 'Item kind')} value={kind} onChange={setKind} disabled={disabled}
      options={[{ value: 'event', label: text('事件', 'Event') }, { value: 'metric', label: text('指标', 'Metric') }]} />
    <Input aria-label={text('CMS 名称', 'CMS name')} value={name} onChange={event => setName(event.target.value)} disabled={disabled} />
    {kind === 'event' ? <Input.TextArea aria-label={text('事件正文', 'Event content')} value={content}
      onChange={event => setContent(event.target.value)} disabled={disabled} /> : <>
      <InputNumber aria-label={text('指标值', 'Metric value')} value={value} onChange={setValue} disabled={disabled} />
      <Input.TextArea aria-label={text('指标维度 JSON', 'Metric dimensions JSON')} value={dimensions}
        onChange={event => setDimensions(event.target.value)} disabled={disabled} />
    </>}
    {canSeed && <Checkbox checked={seed} onChange={event => setSeedSource(event.target.checked ? sourceKey : undefined)} disabled={disabled}>
      {text('明确初始化 owned Mock 演示种子', 'Explicitly initialize the owned Mock demo fixture')}</Checkbox>}
    {invalid && <span role="alert">{text('请核对名称、正文、有限指标值和字符串维度。', 'Check the name, content, finite metric value and string dimensions.')}</span>}
    <Button type="primary" disabled={disabled || !source} onClick={() => {
      try { const body = payload(kind, name, content, value, dimensions); setInvalid(false); onSubmit(body, Boolean(canSeed && seed)); }
      catch { setInvalid(true); }
    }}>{text('明确入队', 'Enqueue explicitly')}</Button>
  </Space>;
}
