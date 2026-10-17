import { useState } from 'react';
import { Alert, Button, Checkbox, Modal, Popconfirm, Space, Table, Typography } from 'antd';
import type { WorkerQuotaBinding, WorkerQuotaRule } from '@/types/agentTeamsQuotas';

interface Props {
  binding: WorkerQuotaBinding;
  rule?: WorkerQuotaRule;
  mocked: boolean;
  canObserve: boolean;
  canSync: boolean;
  busy: boolean;
  zh: boolean;
  onObserve: () => Promise<void>;
  onSync: () => Promise<void>;
}

export default function WorkerQuotaActions({ binding, rule, mocked, canObserve, canSync, busy, zh, onObserve, onSync }: Props) {
  const [open, setOpen] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const text = (cn: string, en: string) => zh ? cn : en;
  const preview = binding.observation;
  return <>
    <Space wrap>
      {canObserve && <Popconfirm title={mocked ? text('读取模拟 Worker 限额？', 'Read simulated Worker limits?') : text('读取真实云端 Worker 限额？', 'Read live cloud Worker limits?')}
        description={text('执行 GetWorker 只读查询；不会修改云端限制。', 'Run a read-only GetWorker query. Cloud limits will not change.')}
        okText={text('确认读取', 'Confirm read')} onConfirm={onObserve}>
        <Button disabled={busy || binding.busy || !binding.canObserve} loading={busy}
          aria-label={text('读取云端', 'Read cloud')}>{text('读取云端', 'Read cloud')}</Button>
      </Popconfirm>}
      {canSync && <Button type="primary" disabled={busy} onClick={() => { setConfirmed(false); setOpen(true); }}>
        {text('检查差异并同步', 'Review difference and sync')}
      </Button>}
    </Space>
    <Modal title={mocked ? text('确认同步模拟限额', 'Confirm simulated quota synchronization') : text('确认写入真实云端限额', 'Confirm live cloud quota write')}
      open={open} onCancel={() => { if (!busy) setOpen(false); }}
      okText={text('确认写入并回读', 'Confirm write and readback')} cancelText={text('取消', 'Cancel')}
      confirmLoading={busy} okButtonProps={{ disabled: !confirmed || !canSync || busy }}
      cancelButtonProps={{ disabled: busy }} maskClosable={!busy}
      onOk={async () => { if (!confirmed || !canSync || busy) return; setOpen(false); await onSync(); }}>
      <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <Typography.Text>{text('目标 Worker', 'Target Worker')}: {binding.workerName}</Typography.Text>
        <Typography.Text>{text('平台资产', 'Platform asset')}: {binding.assetId}</Typography.Text>
        <Typography.Text>{text('云实例范围 / 配置版本', 'Cloud instance scope / configuration version')}: {binding.scopeId} / {binding.cloudVersion}</Typography.Text>
        <Table rowKey="field" size="small" pagination={false} dataSource={[
          { field: 'UsageLimit', before: preview?.usageLimit ?? '—', after: rule?.limit ?? '—' },
          { field: 'LimitType', before: preview?.limitType ?? '—', after: 'token' },
          { field: 'PeriodType', before: preview?.periodType ?? '—', after: 'day' },
        ]} columns={[
          { title: text('配置项', 'Setting'), dataIndex: 'field' },
          { title: text('当前云端配置', 'Current cloud configuration'), dataIndex: 'before' },
          { title: text('确认后的目标', 'Confirmed target'), dataIndex: 'after' },
        ]} />
        <Alert showIcon type={mocked ? 'info' : 'warning'} message={mocked
          ? text('此操作只更新持久化 Mock 状态，再模拟回读；不会调用真实云端。', 'This updates persisted Mock state and simulates readback without calling the live cloud.')
          : text('将按平台规则修改真实 Worker 的限额配置。写入前再次核对云端配置，写入后回读验证。', 'The platform rule will change this live Worker quota. Cloud configuration is reread before writing and verified afterward.')} />
        {!canSync && <Alert type="info" showIcon message={text('预览已失效，请取消后重新读取。', 'The preview is no longer usable. Cancel and read again.')} />}
        <Checkbox checked={confirmed} onChange={event => setConfirmed(event.target.checked)}>
          {text('我已核对 Worker 和差异，确认执行上述写入。', 'I reviewed the Worker and difference and confirm the write above.')}
        </Checkbox>
      </Space>
    </Modal>
  </>;
}
