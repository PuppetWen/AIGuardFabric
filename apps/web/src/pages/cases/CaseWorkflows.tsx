import { useState } from 'react';
import { Alert, Button, Descriptions, Drawer, Input, Modal, Space, Table, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useApiQuery } from '@/api/client';
import { caseWorkflowsApi, type CaseWorkflow } from '@/api/caseWorkflows';
import { useAuthStore } from '@/stores/authStore';

const statuses: Record<string, [string, string]> = {
  queued: ['排队中', 'Queued'], approval: ['待审批', 'Approval required'], waiting: ['等待中', 'Waiting'],
  running: ['执行中', 'Running'], review: ['结果待核对', 'Outcome needs review'], completed: ['步骤已结束', 'Steps finished'],
  aborted: ['已中止', 'Aborted'], cancelled: ['已取消', 'Cancelled'], 'not-started': ['未启动', 'Not started'],
};
const actions: Record<string, [string, string]> = {
  approve: ['批准', 'Approve'], reject: ['拒绝', 'Reject'], cancel: ['取消任务', 'Cancel run'],
  'confirm-completed': ['核实已完成', 'Confirm completed'], retry: ['明确重试当前步骤', 'Retry this step'],
  abort: ['停止后续步骤', 'Stop remaining steps'],
  submitted: ['已提交', 'Submitted'], 'step-started': ['步骤开始', 'Step started'], 'step-finished': ['步骤结束', 'Step finished'],
  wait: ['开始等待', 'Waiting'], 'wait-completed': ['等待结束', 'Wait completed'], 'approval-requested': ['请求审批', 'Approval requested'],
  interrupted: ['执行中断', 'Interrupted'], expired: ['超过时限', 'Expired'], uncertain: ['结果待核对', 'Outcome needs review'],
};
const terminal = (run: CaseWorkflow) => ['completed', 'aborted', 'cancelled', 'not-started'].includes(run.status);

export default function CaseWorkflows(props: {caseId: string; refreshToken: number; onChange: () => void}) {
  const tenant = useAuthStore(state => state.tenant?.id);
  return <WorkflowPanel key={`${tenant}:${props.caseId}`} {...props} />;
}

function WorkflowPanel({ caseId, refreshToken, onChange }: {caseId: string; refreshToken: number; onChange: () => void}) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const label = (values: Record<string, [string, string]>, key: string) => values[key]?.[zh ? 0 : 1] ?? key;
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string>();
  const [pending, setPending] = useState<{run: CaseWorkflow; action: string}>();
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const list = useApiQuery('case-workflows', () => caseWorkflowsApi.list(caseId, page), { key: [caseId, page, refreshToken], refetchInterval: 5000 });
  const detail = useApiQuery('case-workflow', () => caseWorkflowsApi.get(caseId, selected ?? ''), { key: [caseId, selected], enabled: Boolean(selected), refetchInterval: 5000 });
  const data = list.data?.data;
  const run = detail.data?.data.run;
  const handle = (run: CaseWorkflow, action: string) => { setPending({ run, action }); setReason(''); setError(''); };
  const decide = async () => {
    if (!pending) return;
    setBusy(true); setError('');
    try {
      await caseWorkflowsApi.decide(caseId, pending.run.id, pending.run.version, pending.action, reason);
      setPending(undefined); await Promise.all([list.refetch(), detail.refetch()]); onChange();
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Space><Typography.Title level={5} style={{ margin: 0 }}>{text('审批与执行记录', 'Approvals and runs')}</Typography.Title>
      <Button size="small" onClick={() => { void list.refetch(); if (selected) void detail.refetch(); }}>{text('刷新', 'Refresh')}</Button></Space>
    {list.error && <Alert type="error" message={String(list.error)} />}
    {data && !data.durable && <Alert type="warning" message={text('当前为内存模式，重启会丢失执行记录；请配置 PostgreSQL 后使用持久化流程。', 'Memory mode loses runs on restart. Configure PostgreSQL for durable workflows.')} />}
    <Table size="small" rowKey="id" dataSource={data?.items ?? []} loading={list.isLoading}
      pagination={{ current: page, pageSize: 10, total: data?.total ?? 0, onChange: setPage, showSizeChanger: false }} columns={[
        { title: text('剧本', 'Playbook'), render: (_, row: CaseWorkflow) => <Button type="link" onClick={() => setSelected(row.id)}>{row.playbook.name || row.playbook.key}</Button> },
        { title: text('状态', 'Status'), render: (_, row) => <Tag color={row.status === 'review' ? 'orange' : row.status === 'approval' ? 'blue' : undefined}>{label(statuses, row.status)}</Tag> },
        { title: text('步骤进度', 'Step progress'), render: (_, row) => `${row.nextStep} / ${row.playbook.steps.length}` },
      ]} />
    <Drawer width={850} open={Boolean(selected)} onClose={() => setSelected(undefined)} title={text('剧本执行详情', 'Playbook run details')}>
      {detail.error && <Alert type="error" message={String(detail.error)} />}
      {run && <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <Descriptions column={1} size="small" items={[
          { key: 'id', label: 'ID', children: <Typography.Text copyable>{run.id}</Typography.Text> },
          { key: 'state', label: text('状态 / 版本', 'Status / revision'), children: `${label(statuses, run.status)} / ${run.version}` },
          { key: 'step', label: text('当前步骤', 'Current step'), children: run.playbook.steps[run.nextStep]?.name ?? text('已结束', 'Finished') },
          { key: 'wake', label: text('等待结束 / 审批截止', 'Wait ends / approval expires'), children: run.wakeAt || '—' },
          { key: 'limit', label: text('执行截止', 'Execution deadline'), children: run.deadlineAt || '—' },
        ]} />
        {run.reason && <Alert type={run.status === 'completed' ? 'info' : 'warning'} message={run.reason} />}
        {run.status === 'review' && <Alert type="warning" showIcon message={text('先核对处置记录及目标系统，避免重复执行。', 'Inspect containment records and the target system before deciding.')}
          description={text('只有实际确认生效后才能选择“核实已完成”；重试可能重复通知或动作。已完成步骤不会回滚。', 'Confirm completion only after verifying the effect. Retrying may repeat a notification or action. Completed steps are not rolled back.')} />}
        {run.separateApprover && <Alert type="info" message={text('本任务要求另一位管理员审批。', 'This run requires a different administrator to approve.')} />}
        <Typography.Text strong>{text('已保存的步骤与目标', 'Saved steps and targets')}</Typography.Text>
        <Typography.Paragraph><pre style={{ maxHeight: 270, overflow: 'auto', whiteSpace: 'pre-wrap' }}>{JSON.stringify(run.playbook.steps, null, 2)}</pre></Typography.Paragraph>
        <Space wrap>
          {run.status === 'approval' && data?.canApprove && ['approve', 'reject'].map(action => <Button key={action} type={action === 'approve' ? 'primary' : 'default'}
            disabled={run.separateApprover && data.actorId === run.requestedBy.id} onClick={() => handle(run, action)}>{label(actions, action)}</Button>)}
          {run.status === 'review' && data?.canApprove && ['confirm-completed', 'retry', 'abort'].map(action => <Button key={action} onClick={() => handle(run, action)}>{label(actions, action)}</Button>)}
          {!terminal(run) && !['running', 'review'].includes(run.status) && data?.canWrite && (data.canApprove || data.actorId === run.requestedBy.id) &&
            <Button danger onClick={() => handle(run, 'cancel')}>{label(actions, 'cancel')}</Button>}
        </Space>
        <Typography.Text strong>{text('逐步结果', 'Step results')}</Typography.Text>
        {run.trace.map((step, index) => <Alert key={index} type={step.outcome === 'failed' ? 'error' : 'info'} message={`${index + 1}. ${step.name} · ${step.outcome}`} description={step.error || step.note} />)}
        <Table size="small" rowKey="version" pagination={{ pageSize: 8 }} dataSource={run.history} columns={[
          { title: text('时间', 'Time'), dataIndex: 'at' }, { title: text('操作者', 'Actor'), dataIndex: 'actor' },
          { title: text('处理记录', 'Decision'), render: (_, row) => `${label(actions, row.action)}: ${row.note}` },
        ]} />
      </Space>}
    </Drawer>
    <Modal open={Boolean(pending)} title={label(actions, pending?.action ?? '')} confirmLoading={busy} onOk={() => void decide()}
      onCancel={() => !busy && setPending(undefined)} okButtonProps={{ disabled: !reason.trim() }} maskClosable={!busy}>
      <Typography.Paragraph>{text('本次操作绑定以下执行记录版本，请核对目标及步骤。', 'This decision applies to the displayed run revision. Review the target and step.')}</Typography.Paragraph>
      <Typography.Paragraph>{pending?.run.id} · v{pending?.run.version} · {pending?.run.playbook.steps[pending.run.nextStep]?.name}</Typography.Paragraph>
      <Input.TextArea aria-label={text('处理原因', 'Decision reason')} value={reason} maxLength={2000} rows={3} onChange={event => setReason(event.target.value)} />
      {error && <Alert style={{ marginTop: 12 }} type="error" message={error} />}
    </Modal>
  </Space>;
}
