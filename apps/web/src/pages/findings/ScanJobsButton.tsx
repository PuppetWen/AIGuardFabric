import { useState } from 'react';
import { Alert, Button, Collapse, Drawer, Input, Space, Table, Tag, Typography, message } from 'antd';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useSessionAccess } from '@/api/sessionAccess';
import { useApiQuery } from '@/api/client';
import { callApi } from '@/api/transport';
import { useScopedOperation } from '@/components/useScopedOperation';
import { DataState } from '@/components/DataState';
import { ScanForm } from './ScanForm';
import { ScanGuide } from './ScanGuide';

interface Job {
  id: string; name: string; state: string; progress: number; targets: number; findingCount: number;
  findingIds: string[]; riskScore: number | null; error: string | null; summary: string;
  createdAt: string; finishedAt: string | null; llmMocked: boolean | null;
  useLlmJudge: boolean; judgementCount: number; judgementFailures: number;
}
const STATE_LABELS: Record<string, [string, string]> = {
  queued: ['排队', 'Queued'], running: ['执行中', 'Running'], succeeded: ['成功', 'Succeeded'],
  failed: ['失败', 'Failed'], cancelled: ['已取消', 'Cancelled'],
};
const terminal = (job: Job) => ['succeeded', 'failed', 'cancelled'].includes(job.state);

export function ScanJobsButton({ onResults }: { onResults: () => void }) {
  const [open, setOpen] = useState(false);
  const access = useSessionAccess();
  const zh = useTranslation().i18n.language.startsWith('zh');
  if (!access.has('scans:read')) return null;
  return <>
    <Button onClick={() => setOpen(true)}>{zh ? '内容扫描与任务' : 'Content scans'}</Button>
    <Drawer open={open} onClose={() => { setOpen(false); onResults(); }} width={1000} destroyOnClose
      title={zh ? '内容扫描与任务' : 'Content scans and tasks'}>
      {open && <ScanJobs canExecute={access.has('scans:execute')} canReadAssets={access.has('assets:read')} canJudge={access.has('models:write')} />}
    </Drawer>
  </>;
}

function ScanJobs({ canExecute, canReadAssets, canJudge }: { canExecute: boolean; canReadAssets: boolean; canJudge: boolean }) {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const [page, setPage] = useState(1);
  const [state, setState] = useState('');
  const [keyword, setKeyword] = useState('');
  const [submitted, setSubmitted] = useState('');
  const operation = useScopedOperation();
  const jobs = useApiQuery('scan-jobs', () => callApi<{ items: Job[]; total: number }>(
    '/api/v1/scans', () => null as never, { noFallback: true, query: { page, page_size: 10, state, q: keyword, sort: '-created_at' } },
  ), { key: [page, state, keyword], refetchInterval: 3000 });
  const cancel = (job: Job) => operation.run(async current => {
    try {
      await callApi('/api/v1/scans/' + job.id + '/cancel', () => null, { noFallback: true, method: 'POST', body: {} });
      if (current()) await jobs.refetch();
    } catch (reason) {
      if (current()) void message.error(reason instanceof Error ? reason.message : String(reason));
    }
  });
  return <Space direction="vertical" size="large" style={{ width: '100%' }}>
    <Alert type="info" showIcon message={zh ? '只评估本次提交的内容' : 'This scan assesses only submitted content'}
      description={zh
        ? '扫描不会执行命令或访问目标设备。结果分数不等于整项资产的风险分；无命中不能证明资产安全。任务摘要保留，发现可能包含命中证据，请只提交获准检测的数据。'
        : 'A scan does not execute commands or access devices. Its score is not the risk score of the entire asset; no matches do not prove safety. Task summaries persist and findings may contain matched evidence. Submit only data approved for inspection.'} />
    <Collapse items={[{ key: 'guide', label: zh ? '个人与企业操作指南' : 'Personal and enterprise guide', children:
      <ScanGuide /> }]} />
    <ScanForm canExecute={canExecute} canReadAssets={canReadAssets} canJudge={canJudge} onSubmitted={id => {
      setSubmitted(id); setPage(1); setState(''); setKeyword(''); void jobs.refetch();
    }} />
    {submitted && <Alert type="success" message={(zh ? '已受理任务: ' : 'Accepted task: ') + submitted} />}
    <Space wrap>
      <Typography.Title level={5} style={{ margin: 0 }}>{zh ? '任务历史' : 'Task history'}</Typography.Title>
      <Button onClick={() => void jobs.refetch()}>{zh ? '刷新' : 'Refresh'}</Button>
      <Input.Search style={{ width: 235 }} allowClear placeholder={zh ? '任务名称或 ID' : 'Task name or ID'}
        value={keyword} onChange={event => { setKeyword(event.target.value); setPage(1); }}
        onSearch={value => { setKeyword(value); setPage(1); }} />
      {['', 'queued', 'running', 'succeeded', 'failed', 'cancelled'].map(value =>
        <Button key={value} size="small" type={state === value ? 'primary' : 'default'} onClick={() => { setState(value); setPage(1); }}>
          {value ? STATE_LABELS[value][zh ? 0 : 1] : zh ? '全部' : 'All'}
        </Button>)}
    </Space>
    <DataState loading={jobs.isLoading} error={jobs.error} onRetry={() => void jobs.refetch()}>
      <Table<Job> rowKey="id" size="small" dataSource={jobs.data?.data.items ?? []}
        scroll={{ x: 850 }} pagination={{ current: page, pageSize: 10, total: jobs.data?.data.total ?? 0, showSizeChanger: false, onChange: setPage }}
        columns={[
          { title: zh ? '任务' : 'Task', dataIndex: 'name', render: (_, job) => <Space direction="vertical" size={0}>
            <span>{job.name}</span><Typography.Text type="secondary" style={{ fontSize: 11 }}>{job.id}</Typography.Text></Space> },
          { title: zh ? '状态' : 'State', render: (_, job) => <Tag>{STATE_LABELS[job.state]?.[zh ? 0 : 1] ?? job.state}</Tag> },
          { title: zh ? '发现数' : 'Findings', render: (_, job) => job.state === 'succeeded' ? job.findingCount : '—' },
          { title: zh ? '本次评分' : 'Content score', render: (_, job) => job.riskScore ?? '—' },
          { title: zh ? '创建时间' : 'Created', render: (_, job) => new Date(job.createdAt).toLocaleString(zh ? 'zh-CN' : 'en-US') },
          { title: zh ? '操作' : 'Action', render: (_, job) => !terminal(job) &&
            <Button danger size="small" disabled={!canExecute || operation.busy} onClick={() => void cancel(job)}>{zh ? '取消' : 'Cancel'}</Button> },
        ]}
        expandable={{ expandedRowRender: job => <Space direction="vertical" style={{ width: '100%' }}>
          {job.error && <Alert type="error" message={job.error} />}
          {job.judgementFailures > 0 && <Alert type="warning" message={zh ? '部分模型研判未完成，已保留规则结果' : 'Some model judgements failed; rule results were retained'}
            description={zh ? '请检查模型端点、分级、运行时策略与配额；修复后重新提交任务。' : 'Check model endpoints, classification, runtime policies and quotas, then submit a new task.'} />}
          <Typography.Text>{job.summary || (zh ? '尚无已提交的结果' : 'No committed result yet')}</Typography.Text>
          {job.useLlmJudge && terminal(job) && <Typography.Text>{zh ? '完成研判次数: ' : 'Completed judgements: '}{job.judgementCount ?? 0}</Typography.Text>}
          {typeof job.llmMocked === 'boolean' && <Tag>{job.llmMocked ? 'Mock' : zh ? '实际模型研判' : 'Live model judgement'}</Tag>}
          <Space wrap>{(job.findingIds ?? []).map((id, index) =>
            <Link key={id} to={'/findings?finding=' + encodeURIComponent(id)} target="_blank" rel="noreferrer">
              {zh ? '发现' : 'Finding'} {index + 1}
            </Link>)}</Space>
        </Space> }} />
    </DataState>
  </Space>;
}
