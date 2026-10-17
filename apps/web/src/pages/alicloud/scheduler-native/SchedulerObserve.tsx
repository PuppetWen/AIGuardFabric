import { useState } from 'react';
import { Alert, Button, Checkbox, Descriptions, Space } from 'antd';
import type { SchedulerController } from './useSchedulerNative';
import { useSchedulerText } from './text';

export function SchedulerObserve({ flow, canWrite }: { flow: SchedulerController; canWrite: boolean }) {
  const t = useSchedulerText(), [live, setLive] = useState(false), [initialize, setInitialize] = useState(false);
  const { data, busy } = flow, target = data?.sourceTarget;
  if (!target) return <Alert type="info" showIcon message={t('先保存并启用 SchedulerX3 来源配置', 'Save and enable a SchedulerX3 source first')}
    description={t('在上方连接配置中明确 region_id、cluster_id、app_name、模式和凭据。读取本页不会初始化云端。',
      'Configure region_id, cluster_id, app_name, mode and credentials in the connections table above. Reading this page never initializes cloud state.')} />;
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Descriptions size="small" column={2} items={[
      { key: 'app', label: 'AppName', children: target.appName }, { key: 'cluster', label: 'ClusterId', children: target.clusterId },
      { key: 'region', label: 'Region', children: target.region }, { key: 'mode', label: t('模式', 'Mode'), children: target.transportMode },
      { key: 'origin', label: 'RPC origin', children: target.rpcOrigin }, { key: 'version', label: t('配置版本', 'Configuration version'), children: target.configurationVersion },
      { key: 'account', label: t('配置账号 / 身份未验证', 'Configured account / identity unverified'), children: target.configuredAccountId ?? t('未知', 'Unknown') },
    ]} />
    <Alert type="info" showIcon message={t('观察只读取 GetApp 和完整任务列表；不会注册、更新、启停或执行任务。',
      'Observe reads GetApp and the complete job list; it never registers, updates, enables, disables or executes jobs.')} />
    {target.transportMode === 'live' && <Checkbox checked={live} disabled={busy} onChange={event => setLive(event.target.checked)}>
      {t('确认读取此真实云来源', 'Confirm reading this live cloud source')}</Checkbox>}
    {target.mocked && canWrite && data?.canInitMock && <Checkbox checked={initialize} disabled={busy} onChange={event => setInitialize(event.target.checked)}>
      {t('明确初始化此来源的隔离 Mock 示例（仅示例，不代表云任务）', 'Explicitly initialize this source’s isolated Mock fixture (not cloud jobs)')}</Checkbox>}
    <Button loading={busy} disabled={!data?.canObserve || data.busy || busy || (target.transportMode === 'live' && !live)} onClick={() => void flow.observe(live, initialize)}>
      {t('发起新观察（新编号）', 'Observe with a new request ID')}</Button>
    <small>{t('最多 20 个云分页 / 2,000 个任务。列表完整不代表强快照；未知字段保持未知。请求失败后先读取原编号，不自动重发。',
      'At most 20 cloud pages / 2,000 jobs. A complete list is not a strong snapshot; unknown fields remain unknown. After a failed request, read its original ID first; no automatic resubmission.')}</small>
  </Space>;
}
