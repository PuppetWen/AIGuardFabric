import { useState } from 'react';
import { Alert, Button, Checkbox, Popconfirm, Space, Typography } from 'antd';
import { matchingObservation } from './eligibility';
import PublicationTarget from './PublicationTarget';
import { usePublicationText } from './text';
import type { Baseline } from './usePublication';
import type { PublicationState } from './types';
export default function PublicationObservation({ data, baseline, canRead, busy, onObserve, onAdopt }: {
  data: PublicationState; baseline: Baseline | null; canRead: boolean; busy: boolean;
  onObserve: (live: boolean) => void; onAdopt: () => void;
}) {
  const text = usePublicationText(), [live, setLive] = useState(false);
  const liveTarget = data.binding?.transportMode === 'live';
  return <Space direction="vertical" style={{ width: '100%' }}>
    {data.binding ? <PublicationTarget target={data.binding} observation={data.observation} />
      : <Alert type="info" message={data.bindingReason ?? text('尚无有效发布目标绑定。', 'No valid publication target binding.')} />}
    {liveTarget && <Checkbox checked={live} disabled={busy} onChange={event => setLive(event.target.checked)}>{text('确认当前目标的真实只读云观察', 'Confirm a live read-only cloud observation of this target')}</Checkbox>}
    <Space wrap><Button loading={busy} disabled={!canRead || busy || data.busy || !data.canObserve || (!!liveTarget && !live)}
      onClick={() => onObserve(live)}>{text('明确读取当前云内容', 'Explicitly read current cloud content')}</Button>
      <Popconfirm title={text('采用最新观察和状态版本为新基线？政策选择保留，旧预览作废。', 'Adopt the latest observation and state revision as the new baseline? Policy selections remain and the old preview is discarded.')}
        okText={text('确认采用观察基线', 'Confirm adopting observation baseline')} onConfirm={onAdopt}>
        <Button disabled={busy || !matchingObservation(data, data.observation)}>{text('采用最新观察基线', 'Adopt latest observation baseline')}</Button>
      </Popconfirm></Space>
    <Typography.Text>{text('草稿仍使用状态版本 / 观察', 'Draft still uses state revision / observation')}: {baseline ? `${baseline.stateVersion} / ${baseline.observation.id}` : '—'}</Typography.Text>
    {baseline && <Typography.Text>{text('草稿基线 SHA256', 'Draft baseline SHA256')}: {baseline.observation.contentHash}</Typography.Text>}
    <Alert type="info" message={text('本地 GET 刷新不会查询云、自动采用新基线或重发。观察有效 5 分钟；失败后需重新明确观察。', 'A local GET refresh neither queries the cloud, adopts a new baseline nor retries a write. Observations last five minutes; a failed observation requires an explicit new observation.')} />
  </Space>;
}
