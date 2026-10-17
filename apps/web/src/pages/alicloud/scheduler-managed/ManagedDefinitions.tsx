import { Button, Space, Table, Typography } from 'antd';
import type { ManagedController } from './useManagedJobs';
import { useText } from './text';
export function ManagedDefinitions({ flow }: { flow: ManagedController }) {
  const t = useText(), data = flow.data;
  if (!data) return null;
  const rows = data.target ? data.definitions.filter(row => row.scopeId === data.target?.scopeId) : data.definitions.slice(0, 50);
  return <section aria-label={t('受管任务定义', 'Managed job definitions')}><Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{t('受管任务定义', 'Managed job definitions')}</Typography.Title>
    <Typography.Text>{t('这里是本地已提交定义，不证明云端当前启用、callback 关联或任务已执行。当前来源最多六类；来源停用时有界显示最多 50 条历史定义。',
      'These are committed local definitions, not proof of current cloud enable, callback association or execution. The current source has at most six kinds; a disabled source shows at most 50 historical definitions.')} </Typography.Text>
    <Table size="small" rowKey={row => `${row.scopeId}:${row.kind}`} pagination={{ pageSize: 50, showSizeChanger: false }} dataSource={rows} columns={[
      { title: t('类型 / 执行器', 'Kind / executor'), render: (_, row) => `${row.kind} → ${row.kind === 'report' ? 'report-generate' : row.kind === 'archive' ? 'cold-archive' : row.kind}` },
      { title: 'Job ID', dataIndex: 'jobId' }, { title: 'total', dataIndex: 'total' },
      { title: t('原受管请求', 'Original managed request'), render: (_, row) => <Button disabled={flow.reading}
        onClick={() => void flow.readOriginal(row.requestId, 'apply')}>{row.requestId}</Button> },
    ]} />
  </Space></section>;
}
