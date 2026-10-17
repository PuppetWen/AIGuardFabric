import { Alert, Button, Descriptions, Space, Typography } from 'antd';
import type { ManagedController } from './useManagedJobs';
import { useText } from './text';
export function ManagedReceipt({ flow, canManage }: { flow: ManagedController; canManage: boolean }) {
  const t = useText(), row = flow.operation;
  if (!row) return null;
  const accepted = row.completionState === 'complete' && row.originalWrite?.status === 'accepted';
  return <section aria-label={t('原受管请求回执', 'Original managed request receipt')}>
    <Space direction="vertical" style={{ width: '100%' }}>
      <Typography.Title level={5}>{t('原受管请求回执', 'Original managed request receipt')}</Typography.Title>
      <Alert type={accepted ? 'info' : 'warning'} message={`${row.status} · ${row.completionState} · ${row.originalWrite?.status ?? 'unknown'} · readback=${row.readback}`}
        description={t('Accepted 仅表示原修改被接受；Matched 是独立读回匹配。Unknown 永不因后来匹配升级为成功，亦不证明任务执行或消费者生效。',
          'Accepted describes the original change only; Matched is an independent readback match. Unknown never becomes success after a match and never proves job execution or consumer activation.')} />
      <Descriptions column={1} size="small" items={[
        { key: 'id', label: t('原请求编号', 'Original request ID'), children: row.requestId },
        { key: 'preview', label: t('原预览编号', 'Original preview ID'), children: row.previewId },
        { key: 'action', label: t('原动作 / 类型', 'Original action / kind'), children: `${row.action} · ${row.kind} → ${row.runtimeName}` },
        { key: 'job', label: 'Job ID', children: row.jobId ?? 'unknown' },
        { key: 'original', label: t('原配置版本 / 来源', 'Original configuration version / source'), children: `${row.configurationVersion} · ${row.target.clusterId} · ${row.target.appName} · ${row.target.transportMode}` },
        { key: 'current', label: t('当前来源匹配 / 版本', 'Current source match / version'), children: `${row.sourceCurrent ?? 'unknown'} / ${row.currentConfigurationVersion ?? 'unknown'}` },
        { key: 'lease', label: t('原领取租约', 'Original claim lease'), children: row.expiresAt },
        { key: 'readback', label: t('最近独立读回', 'Last independent readback'), children: row.readbackAt ?? '—' },
      ]} />
      <Typography.Text>callbackBindingEnforced=false · deploymentVerified=unknown · callbackConfigured=unknown · consumerApplied=unknown · cloudCasAvailable=false</Typography.Text>
      {row.completionState === 'pending_audit' && <Alert type="warning" message={t('结果已封存但本地终态/审计尚未完成；显式本地恢复不会调用云。',
        'The result is staged but local completion/audit is pending. Explicit local recovery never calls cloud.')} />}
      {row.archived && <Alert type="info" message={t('正文已归档，永久事实与原写状态保留；原编号不会重新派发。', 'Body archived; permanent fact and original write status remain, with no redispatch of this ID.')} />}
      <Space wrap>
        <Button disabled={flow.reading} onClick={() => void flow.readOriginal(row.requestId, 'apply')}>{t('GET 读取此原回执', 'GET this original receipt')}</Button>
        <Button disabled={!canManage || flow.busy || !row.allowedActions.includes('recover_local')} onClick={() => void flow.localAction('recover_local')}>
          {t('显式恢复本地终态与审计（不调用云）', 'Recover local completion/audit explicitly (no cloud)')}</Button>
        <Button disabled={!canManage || flow.busy || !row.allowedActions.includes('observe')} onClick={() => void flow.localAction('observe')}>
          {t('独立只读观察原任务', 'Independently observe the original job')}</Button>
      </Space>
    </Space>
  </section>;
}
