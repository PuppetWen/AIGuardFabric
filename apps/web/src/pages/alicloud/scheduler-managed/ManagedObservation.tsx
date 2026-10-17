import { Alert, Button, Checkbox, Pagination, Space, Typography } from 'antd';
import { useState } from 'react';
import type { ManagedController } from './useManagedJobs';
import { useText } from './text';
export function ManagedObservation({ flow, canManage }: { flow: ManagedController; canManage: boolean }) {
  const t = useText(), [live, setLive] = useState(false), [init, setInit] = useState(false);
  const native = flow.nativeState, target = native?.sourceTarget, receipt = flow.observation;
  const observed = receipt ?? native?.latestObservation, page = receipt?.observation;
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{t('先观察当前来源', 'Observe the current source first')}</Typography.Title>
    <Typography.Text>{target ? `${target.mocked ? 'Mock' : target.transportMode} · ${target.region} · ${target.clusterId} · ${target.appName} · ${target.configurationVersion}` : t('来源未启用或不可用', 'Source disabled or unavailable')}</Typography.Text>
    {target?.mocked && <Checkbox checked={init} disabled={!canManage || !native?.canInitMock} onChange={event => setInit(event.target.checked)}>
      {t('明确初始化该固定 Mock 示例', 'Explicitly initialize this fixed Mock example')}</Checkbox>}
    {target?.transportMode === 'live' && <Checkbox checked={live} onChange={event => setLive(event.target.checked)}>
      {t('确认只读真实云观察', 'Confirm a read-only live cloud observation')}</Checkbox>}
    <Button loading={flow.busy} disabled={!native?.canObserve || native.busy || flow.busy || (target?.transportMode === 'live' && !live)
      || (target?.mocked && !observed?.available && !init)} onClick={() => void flow.observe(live, init)}>{t('提交新编号的完整观察', 'Submit a complete observation with a new ID')}</Button>
    {flow.observationRequestId && <Space wrap><Typography.Text>{t('本次观察原编号', 'This observation request ID')}: {flow.observationRequestId}</Typography.Text>
      <Button disabled={flow.reading} onClick={() => void flow.readObservation(flow.observationRequestId)}>{t('读取本次观察原回执', 'Read this observation receipt')}</Button></Space>}
    {observed && <><Typography.Text>{t('观察原编号', 'Original observation ID')}: {observed.requestId} · {observed.status} · {observed.total ?? 'unknown'}</Typography.Text>
      <Button disabled={flow.reading} onClick={() => void flow.readObservation(observed.requestId)}>{t('GET 读取原观察（不重派）', 'GET original observation (no redispatch)')}</Button>
      {page && <div role="group" aria-label={t('受管任务观察分页', 'Managed observed job pagination')}><Pagination current={page.page} pageSize={page.pageSize} total={page.total}
        showSizeChanger={false} disabled={flow.reading} onChange={page => receipt && void flow.readObservation(receipt.requestId, page)} /></div>}</>}
    <Alert type="info" message={t('GET、分页和刷新不初始化、不注册任务。观察成功也不证明云回调已部署。', 'GET, paging and refresh never initialize or register jobs. A successful observation does not prove a cloud callback deployment.')} />
  </Space>;
}
