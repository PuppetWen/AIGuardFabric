import { Alert, Button, Checkbox, Descriptions, Popconfirm, Space, Typography } from 'antd';
import { useEffect, useState } from 'react';
import type { ManagedController } from './useManagedJobs';
import { useText } from './text';

export function ManagedPreview({ flow, canManage }: { flow: ManagedController; canManage: boolean }) {
  const t = useText(), [noCas, setNoCas] = useState(false), [callback, setCallback] = useState(false);
  const [live, setLive] = useState(false), [overlap, setOverlap] = useState(false), row = flow.preview;
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  if (!row) return null;
  const target = row.target, unknown = flow.data?.unknownScopes.filter(item => !item.resource
    || (item.resource.tenant === target.tenant && item.resource.clusterId === target.clusterId && item.resource.appName === target.appName)) ?? [];
  const needsRisk = unknown.length > 0, needsLive = target.transportMode === 'live';
  const current = flow.data?.target?.fingerprint === target.fingerprint && flow.data.target.configurationVersion === target.configurationVersion;
  const expired = !row.expiresAt || Date.parse(row.expiresAt) <= now;
  const ready = canManage && row.canApply && !row.archived && current && !expired && !flow.busy && !flow.intentLocked
    && !flow.attempted && noCas && callback && (!needsLive || live) && (!needsRisk || overlap);
  return <section aria-label={t('单动作预览', 'Single-action preview')}><Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{t('单动作预览', 'Single-action preview')}</Typography.Title>
    <Descriptions column={1} size="small" items={[
      { key: 'id', label: t('原预览编号', 'Original preview ID'), children: row.id },
      { key: 'version', label: t('原配置版本', 'Original configuration version'), children: row.configurationVersion },
      { key: 'expires', label: t('预览有效至', 'Preview expires at'), children: row.expiresAt ?? '—' },
      { key: 'fingerprint', label: t('预览指纹', 'Preview fingerprint'), children: row.fingerprint },
      { key: 'operation', label: t('已领取请求', 'Claimed request'), children: row.operationId ?? '—' },
    ]} />
    {row.archived ? <Alert type="info" message={t('预览正文已归档；永久编号只读，不能再次执行。', 'Preview body archived; the permanent ID is read-only and cannot execute again.')} />
      : <Typography.Paragraph><pre style={{ maxHeight: 360, overflow: 'auto' }}>{JSON.stringify({ before: row.before, desired: row.desired }, null, 2)}</pre></Typography.Paragraph>}
    <Alert type="warning" message={t('先核对旧值和新值；本次只有一个动作，不会顺带启用、绑定或部署。',
      'Review old and new values; this intent performs one action and never implicitly enables, binds or deploys.')} />
    <Checkbox checked={noCas} onChange={event => setNoCas(event.target.checked)}>{t('确认云端没有 CAS；读取指纹不是原子云锁', 'Confirm no cloud CAS; a read fingerprint is not an atomic cloud lock')}</Checkbox>
    <Checkbox checked={callback} onChange={event => setCallback(event.target.checked)}>{t('确认回调绑定未强制执行，部署与消费者仍未知', 'Confirm callback binding is unenforced and deployment/consumers remain unknown')}</Checkbox>
    {needsLive && <Checkbox checked={live} onChange={event => setLive(event.target.checked)}>{t('确认本次单独真实云修改', 'Confirm this separate live cloud change')}</Checkbox>}
    {needsRisk && <><Alert type="warning" message={t('同租户、集群和应用存在旧 Unknown；修改账号标签或来源不会消除风险。须原写租约后完成新观察，并独立确认重叠风险。',
      'An older Unknown exists for this tenant, cluster and app. Changing account labels or source never removes that risk. Complete a new observation after its lease, then confirm overlap separately.')} />
      <Typography.Text>{unknown.map(item => item.requestId).join(' · ')}</Typography.Text>
      <Checkbox checked={overlap} onChange={event => setOverlap(event.target.checked)}>{t('确认旧远端可能仍在运行，独立承担新写重叠风险', 'Confirm old remote work may still run and accept the separate new-write overlap risk')}</Checkbox></>}
    <Popconfirm title={t('仅发送这一个新意图？', 'Send only this one new intent?')} okText={t('确认单次提交', 'Confirm single submission')}
      disabled={!ready} onConfirm={() => {
        if (row.expiresAt && Date.parse(row.expiresAt) > Date.now())
          return flow.apply({ noCas, callback, live, unknown: overlap });
      }}>
      <Button type="primary" disabled={!ready}>{t('提交单次受管修改', 'Submit one managed change')}</Button>
    </Popconfirm>
    {flow.attempted && <Alert type="info" message={t('该预览已尝试领取；保留原请求编号，读取回执，不重发。', 'This preview has already been attempted; keep the original request ID and read its receipt without redispatch.')} />}
  </Space></section>;
}
