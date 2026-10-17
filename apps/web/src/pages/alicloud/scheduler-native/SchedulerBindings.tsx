import { useState } from 'react';
import { Alert, Button, Checkbox, Descriptions, Popconfirm, Space, Table, Typography } from 'antd';
import { SCHEDULER_TASKS } from '../scheduler-registration/tasks';
import { adoptable, useSchedulerText } from './text';
import type { ObservationReceipt, SchedulerJob, SchedulerKind } from './types';
import type { SchedulerController } from './useSchedulerNative';
import { SchedulerJobs } from './SchedulerJobs';
import { SchedulerBindingProofs } from './SchedulerBindingProofs';

export function SchedulerBindings({ flow, canWrite }: { flow: SchedulerController; canWrite: boolean }) {
  const t = useSchedulerText(), { data, receipt, busy } = flow;
  const [baseVersion, setBaseVersion] = useState(data!.bindings.version);
  const [baseline, setBaseline] = useState<ObservationReceipt | null>(null), [confirm, setConfirm] = useState(false);
  const [choices, setChoices] = useState<Partial<Record<SchedulerKind, string>>>(() => Object.fromEntries(data!.bindings.items.map(row => [row.kind, row.jobId])));
  const [review, setReview] = useState<{ version: number; observation: ObservationReceipt; assignments: { kind: SchedulerKind; job_id: string }[] } | null>(null);
  const [disableVersion, setDisableVersion] = useState<number | null>(null);
  if (!data) return null;
  const selected = SCHEDULER_TASKS.flatMap(task => choices[task.kind] ? [{ kind: task.kind, job_id: choices[task.kind]! }] : []);
  const ready = !!baseline && adoptable(data, baseline) && data.canBind && canWrite && !busy;
  const adopt = () => {
    if (busy || !canWrite) return;
    setBaseVersion(data.bindings.version); setConfirm(false); setReview(null);
    setBaseline(adoptable(data, receipt) ? receipt : null);
  };
  const assign = (kind: SchedulerKind, job: SchedulerJob) => {
    if (!ready || receipt?.requestId !== baseline?.requestId || job.enabled !== true || !job.httpJob) return;
    setConfirm(false); setChoices(prior => {
      const next = { ...prior }; SCHEDULER_TASKS.forEach(task => { if (next[task.kind] === job.id) delete next[task.kind]; });
      next[kind] = job.id; return next;
    });
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <SchedulerBindingProofs binding={data.bindings} reading={flow.reading} onRead={id => void flow.readReceipt(id)} />
    <Typography.Title level={5}>{t('本地任务关联草稿', 'Local task association draft')}</Typography.Title>
    <Alert type="warning" showIcon message={t('当前 callbackBindingEnforced=false：保存关联尚不约束回调执行', 'Currently callbackBindingEnforced=false: saved associations do not constrain callback execution')}
      description={t('部署状态、回调配置、云注册与实际执行仍未知。绑定成功不能当作六类任务可运行的证明。',
        'Deployment, callback configuration, cloud registration and execution remain unknown. A saved binding does not prove that the six tasks can run.')} />
    <Descriptions size="small" column={2} items={[
      { key: 'status', label: t('当前关联状态', 'Current association status'), children: data.bindings.status },
      { key: 'versions', label: t('保存使用版本 / 最新版本', 'Save uses version / latest version'), children: `${baseVersion} / ${data.bindings.version}` },
      { key: 'id', label: t('已采用观察编号', 'Adopted observation ID'), children: baseline?.requestId ?? t('未采用', 'Not adopted') },
      { key: 'intent', label: t('最后本地操作编号', 'Last local intent ID'), children: flow.intentId || '—' },
    ]} />
    <Button disabled={!canWrite || busy} onClick={adopt}>{t('明确采用最新本地版本与所读观察（保留选择）', 'Adopt latest local version and the read observation (keep selections)')}</Button>
    {baseVersion !== data.bindings.version && <Alert type="warning" message={t('最新版本已变化。重新读取仅供比较；先检查草稿，再明确采用，不会自动重发。',
      'The latest version changed. Reload only compares it; review the draft and explicitly adopt. No automatic resubmission.')} />}
    <Table size="small" rowKey="kind" pagination={false} dataSource={SCHEDULER_TASKS} columns={[
      { title: t('平台任务 / 执行器', 'Platform task / executor'), render: (_, task) => `${task.kind} → ${task.runtimeName}` },
      { title: 'JobId', render: (_, task) => <Typography.Text code>{choices[task.kind] ?? t('未选择', 'Unselected')}</Typography.Text> },
      { title: t('操作', 'Action'), render: (_, task) => <Button size="small" disabled={!canWrite || busy || !choices[task.kind]} onClick={() => {
        setConfirm(false); setChoices(prior => { const next = { ...prior }; delete next[task.kind]; return next; });
      }}>{t('移除选择', 'Remove selection')}</Button> },
    ]} />
    <Checkbox checked={confirm} disabled={!ready} onChange={event => setConfirm(event.target.checked)}>
      {t('确认整体替换本地关联；空列表明确清空；不会创建或变更云任务', 'Confirm full replacement of local associations; an empty list clears them; no cloud jobs are created or changed')}</Checkbox>
    <Space>
      <Popconfirm title={t(`确认保存 ${selected.length} 项本地关联？`, `Save ${selected.length} local associations?`)}
        okText={t('确认本地保存', 'Confirm local save')} onOpenChange={open => { if (open && baseline) setReview({ version: baseVersion, observation: baseline, assignments: selected }); }}
        onConfirm={() => review ? flow.replace(review.assignments, review.version, review.observation) : undefined}>
        <Button disabled={!ready || !confirm}>{t('保存本地关联', 'Save local associations')}</Button>
      </Popconfirm>
      <Popconfirm title={t('仅停用本地关联，云任务和部署服务不会停用', 'Disable local associations only; cloud jobs and deployed services remain unchanged')}
        okText={t('确认本地停用', 'Confirm local disable')} onOpenChange={open => { if (open) setDisableVersion(baseVersion); }}
        onConfirm={() => disableVersion === null ? undefined : flow.disable(disableVersion)}>
        <Button disabled={!canWrite || busy || !data.bindings.locallyEnabled}>{t('停用本地关联', 'Disable local associations')}</Button>
      </Popconfirm>
    </Space>
    <small>{t('观察完成后 300 秒是人工采用门槛，不是已保存关联的执行授权有效期。旧观察、当前来源改变或资格失败需重新观察与核对。',
      'The 300-second observation window is an adoption gate, not an execution authorization lifetime for saved bindings. Reobserve and review stale evidence, changed sources or failed eligibility.')}</small>
    {receipt && <SchedulerJobs receipt={receipt} reading={flow.reading} selectable={ready && receipt.requestId === baseline?.requestId}
      assignments={choices} onAssign={assign} onPage={page => void flow.readReceipt(receipt.requestId, page)} />}
  </Space>;
}
