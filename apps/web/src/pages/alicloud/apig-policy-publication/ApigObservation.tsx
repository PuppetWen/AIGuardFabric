import { useState } from 'react';
import { Alert, Button, Checkbox, Descriptions, Space, Table, Typography } from 'antd';
import type { ApigPublicationState } from '@/types/apigPolicyPublication';
import type { Baseline } from './useApigPublication';
import { useApigText } from './text';

export default function ApigObservation({ data, baseline, busy, onObserve, onAdopt }: {
  data: ApigPublicationState; baseline: Baseline | null; busy: boolean;
  onObserve: (live: boolean, initialize: boolean) => void; onAdopt: () => void;
}) {
  const text = useApigText(), [live, setLive] = useState(false), [initialize, setInitialize] = useState(false);
  const target = data.binding;
  return <Space direction="vertical" style={{ width: '100%' }}>
    {target ? <Descriptions size="small" column={2} bordered items={[
      { key: 'source', label: text('实际来源', 'Actual source'), children: target.sourceLabel },
      { key: 'mode', label: text('实际模式 / 地域', 'Effective mode / region'), children: `${target.transportMode} / ${target.region}` },
      { key: 'scope', label: 'Scope / configuration', children: `${target.targetScopeId} / v${target.configurationVersion}` },
      { key: 'target', label: text('五 ID', 'Five IDs'), children: Object.values(target.binding).join(' / ') },
    ]} /> : <Alert type="warning" message={data.bindingReason ?? text('尚未配置可信目标', 'No trusted target is configured')} />}
    <Alert type="info" message={text('GET 只读本地状态；明确观察才执行 GetHttpApi、GetPolicy、GetPolicyAttachment。',
      'GET reads local state only. Explicit observation runs GetHttpApi, GetPolicy and GetPolicyAttachment.')}
      description={text('观察 fingerprint 只用于比较，不是云 CAS；部署/API 关联存在不证明独占策略、消费者加载或网络可达。',
        'The observation fingerprint is comparison evidence, not cloud CAS. A deployment/API reference does not prove exclusive ownership, consumer loading or network reachability.')} />
    {target?.transportMode === 'live' && <Checkbox checked={live} disabled={busy} onChange={event => setLive(event.target.checked)}>
      {text('确认对上述 Live 目标执行只读观察', 'Confirm read-only observation of the Live target above')}</Checkbox>}
    {data.canInitializeMockFixture && <Checkbox checked={initialize} disabled={busy} onChange={event => setInitialize(event.target.checked)}>
      {text('明确初始化受控 Mock fixture（仅该五 ID，不创建实云资源）', 'Explicitly initialize the owned Mock fixture (these five IDs only; no live resources)')}</Checkbox>}
    <Button disabled={busy || data.busy || !data.canObserve || (target?.transportMode === 'live' && !live)} onClick={() => onObserve(live, initialize)}>
      {text('明确观察当前 APIG 目标', 'Explicitly observe the current APIG target')}</Button>
    {data.observation && <>
      {data.observation.reason && <Alert type="warning" message={data.observation.reason} />}
      <Typography.Text>{text('最新观察', 'Latest observation')}: {data.observation.id} / {data.observation.observedAt}</Typography.Text>
      <Typography.Text>{text('指纹 / 配置 hash', 'Fingerprint / config hash')}: {data.observation.fingerprint} / {data.observation.configHash}</Typography.Text>
      <Table size="small" rowKey="managedLimit" pagination={false} dataSource={data.observation.slots} columns={[
        { title: text('实际已有 Global slot', 'Actual existing Global slot'), dataIndex: 'managedLimit' },
        { title: text('当前阈值', 'Current threshold'), dataIndex: 'currentLimit', render: value => value ?? text('未知', 'Unknown') },
        { title: text('可支持 / 原因', 'Supported / reason'), render: (_, row) => `${row.supported} / ${row.reason ?? '—'}` },
      ]} />
      <Button disabled={busy || !data.observation.usable} onClick={onAdopt}>{text('明确采用最新观察为草稿基线', 'Explicitly adopt the latest observation as the draft baseline')}</Button>
    </>}
    <Typography.Text>{text('草稿仍使用状态版本 / 观察', 'Draft still uses state revision / observation')}: {baseline ? `${baseline.stateVersion} / ${baseline.observation.id}` : '—'}</Typography.Text>
  </Space>;
}
