import { useState } from 'react';
import { Button, Popconfirm, Space, Table, Typography } from 'antd';
import type { SchedulerController } from './useSchedulerNative';
import type { ObservationSummary } from './types';
import { useSchedulerText } from './text';

export function SchedulerHistory({ flow, canWrite }: { flow: SchedulerController; canWrite: boolean }) {
  const t = useSchedulerText(), [selected, setSelected] = useState<string[]>([]);
  const [review, setReview] = useState<{ ids: string[]; generation: number } | null>(null);
  const { data, receipt, busy } = flow; if (!data) return null;
  const rows = [...data.recentObservations];
  if (receipt && !rows.some(row => row.requestId === receipt.requestId)) rows.unshift(receipt);
  const limit = Math.min(100, data.limits.maxArchive);
  const eligible = new Map(rows.map(row => [row.requestId, row]));
  const invalidSelection = selected.some(id => !eligible.get(id)?.archivable || !eligible.get(id)?.allowedActions.includes('archive'));
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{t('观察台账与归档', 'Observation ledger and archive')}</Typography.Title>
    <Typography.Text>{`${t('正文 / 累计归档 / 字节 / 代次', 'Bodies / archived / bytes / generation')}: ${data.detailedObservationCount} / ${data.archivedCount} / ${data.storedContentBytes} / ${data.generation}`}</Typography.Text>
    <Table<ObservationSummary> rowKey="requestId" size="small" pagination={{ pageSize: 50, showSizeChanger: false }} dataSource={rows}
      rowSelection={canWrite ? { selectedRowKeys: selected, onChange: ids => setSelected(ids.map(String)),
        getCheckboxProps: row => ({ disabled: busy || !row.archivable || !row.allowedActions.includes('archive') }) } : undefined}
      columns={[
        { title: 'Request UUID', dataIndex: 'requestId' }, { title: t('状态', 'Status'), dataIndex: 'status' },
        { title: t('任务数', 'Jobs'), render: (_, row) => row.total ?? t('未知', 'Unknown') },
        { title: t('读取', 'Read'), render: (_, row) => <Button disabled={flow.reading} onClick={() => void flow.readReceipt(row.requestId)}>{t('读取原编号', 'Read original ID')}</Button> },
      ]} />
    <Popconfirm title={t(`确认归档 ${selected.length} 条观察正文？`, `Archive ${selected.length} observation bodies?`)}
      description={t('原编号与永久事实保留，分页正文被移除；不会删除云任务或部署。此操作不会取消云端工作。',
        'Original IDs and permanent facts remain; paginated bodies are removed. No cloud jobs or deployments are deleted, and cloud work is not cancelled.')}
      okText={t('确认归档正文', 'Confirm body archive')} onOpenChange={open => { if (open) setReview({ ids: [...selected], generation: data.generation }); }}
      onConfirm={async () => { if (review) await flow.archive(review.ids, review.generation); }}>
      <Button disabled={!canWrite || busy || invalidSelection || selected.length === 0 || selected.length > limit}>{t('归档已选正文', 'Archive selected bodies')} ({selected.length}/{limit})</Button>
    </Popconfirm>
    {selected.length > 0 && <Button disabled={busy} onClick={() => setSelected([])}>{t('清除归档选择', 'Clear archive selection')}</Button>}
    <small>{t('列表显示最近 50 条正文台账；更早编号可在上方直接读取。配置停用后仍可读取及按权限归档。请求租约过期只表示本地中断，不能证明远端取消。',
      'The list contains the latest 50 body records; read older IDs directly above. Disabled configuration still permits receipt reads and authorized local archive. An expired lease means local interruption, not remote cancellation.')}</small>
  </Space>;
}
