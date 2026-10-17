import { Alert, Descriptions, Pagination, Select, Space, Table, Typography } from 'antd';
import { SCHEDULER_TASKS } from '../scheduler-registration/tasks';
import type { ObservationReceipt, SchedulerJob, SchedulerKind } from './types';
import { useSchedulerText } from './text';

export function SchedulerJobs({ receipt, reading, selectable, assignments, onAssign, onPage }: {
  receipt: ObservationReceipt; reading: boolean; selectable: boolean; assignments: Partial<Record<SchedulerKind, string>>;
  onAssign: (kind: SchedulerKind, job: SchedulerJob) => void; onPage: (page: number) => void;
}) {
  const t = useSchedulerText(), observed = receipt.observation;
  const unknown = t('未知', 'Unknown'), bool = (value: boolean | null) => value === null ? unknown : value ? t('是', 'Yes') : t('否', 'No');
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{t('原观察回执', 'Original observation receipt')}</Typography.Title>
    <Descriptions column={2} size="small" items={[
      { key: 'id', label: 'Request UUID', children: receipt.requestId }, { key: 'status', label: t('状态', 'Status'), children: receipt.status },
      { key: 'original', label: t('原状态', 'Original status'), children: receipt.originalStatus },
      { key: 'total', label: t('观察任务总数', 'Observed jobs'), children: receipt.total ?? unknown },
      { key: 'app', label: 'AppId', children: receipt.appId ?? unknown },
      { key: 'scope', label: t('原配置 / 当前来源匹配', 'Original configuration / matches current source'), children: `${receipt.originalTarget?.configurationVersion ?? unknown} / ${bool(receipt.current)}` },
      { key: 'source', label: t('原来源：区域 / 集群 / 应用', 'Original source: region / cluster / application'),
        children: receipt.originalTarget ? `${receipt.originalTarget.region} / ${receipt.originalTarget.clusterId} / ${receipt.originalTarget.appName}` : unknown },
      { key: 'origin', label: t('原 RPC 地址 / 模式', 'Original RPC origin / mode'),
        children: receipt.originalTarget ? `${receipt.originalTarget.rpcOrigin} / ${receipt.originalTarget.transportMode}` : unknown },
      { key: 'evidence', label: t('部署 / 授权 / 回调可达性', 'Deployment / authorization / callback reachability'), children: `${unknown} / ${unknown} / ${unknown}` },
    ]} />
    {receipt.reason && <Alert type="warning" message={receipt.reason} />}
    {!observed && <Alert type="info" message={t('当前没有可读取的观察正文；原事实保留。归档或失败不能解释为零任务。',
      'No observation body is available; the original fact remains. Archived or failed does not mean zero jobs.')} />}
    {observed && <>
      <Alert type="info" message={t('HTTP 类型不证明回调地址、Token、授权或连通性正确；这里只显示字段存在性和摘要。',
        'HTTP type does not verify callback URLs, tokens, authorization or reachability; only carrier presence and digests are shown.')} />
      <Table<SchedulerJob> size="small" rowKey="id" loading={reading} pagination={false} dataSource={observed.jobs} scroll={{ x: 1000 }} columns={[
        { title: 'JobId', dataIndex: 'id', render: (id: string) => <Typography.Text code>{id}</Typography.Text> },
        { title: t('名称', 'Name'), dataIndex: 'name' },
        { title: t('启用 / 类型', 'Enabled / type'), render: (_, job) => `${bool(job.enabled)} / ${job.kind ?? unknown}` },
        { title: t('时间表达式 / 时区', 'Schedule / timezone'), render: (_, job) => `${job.schedule.expression ?? unknown} / ${job.schedule.zone ?? unknown}` },
        { title: t('HTTP 配置证据', 'HTTP configuration evidence'), render: (_, job) => <span>{`parameters=${job.http.parameters}; handler=${job.http.handler}; verified=false`}</span> },
        { title: t('手工指派平台任务', 'Assign platform task'), render: (_, job) => <Select style={{ minWidth: 180 }} aria-label={`${t('指派任务', 'Assign task')} ${job.id}`}
          value={SCHEDULER_TASKS.find(task => assignments[task.kind] === job.id)?.kind} placeholder={t('不自动选择', 'No default selection')}
          disabled={!selectable || reading || job.enabled !== true || !job.httpJob}
          options={SCHEDULER_TASKS.map(task => ({ value: task.kind, label: `${task.kind} → ${task.runtimeName}` }))}
          onChange={(kind: SchedulerKind) => onAssign(kind, job)} /> },
      ]} />
      <div aria-label={t('观察任务分页', 'Observed job pagination')}>
        <Pagination current={observed.page} pageSize={observed.pageSize} total={observed.total} showSizeChanger={false} disabled={reading}
          onChange={onPage} showTotal={total => `${t('观察任务', 'Observed jobs')}: ${total}`} />
      </div>
    </>}
  </Space>;
}
