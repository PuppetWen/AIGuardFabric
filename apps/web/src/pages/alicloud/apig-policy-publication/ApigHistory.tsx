import { useState } from 'react';
import { Alert, Button, Popconfirm, Space, Table, Typography } from 'antd';
import type { ApigOperation, ApigPublicationState } from '@/types/apigPolicyPublication';
import { useApigText } from './text';

export default function ApigHistory({ data, canWrite, busy, onRead, onRollback, onArchive }: {
  data: ApigPublicationState; canWrite: boolean; busy: boolean; onRead: (id: string) => void; onRollback: (id: string) => void;
  onArchive: (ids: string[], generation: number) => Promise<void>;
}) {
  const text = useApigText(), [selected, setSelected] = useState<string[]>([]);
  const [review, setReview] = useState<{ ids: string[]; generation: number } | null>(null);
  const archivable = (row: ApigOperation) => row.archivable && row.allowedActions.includes('archive');
  const valid = selected.length > 0 && selected.length <= data.limits.maxArchive && selected.every(id => data.operations.some(row => row.requestId === id && archivable(row)));
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('可信历史、回执与容量归档', 'Trusted history, receipts and capacity archive')}</Typography.Title>
    <Typography.Text>{text('详情条数 / 上限；正文 bytes / 上限；已归档', 'Detailed runs / limit; body bytes / limit; archived')}: {data.detailedRunCount}/{data.limits.maxDetailedRuns}; {data.storedContentBytes}/{data.limits.maxStoredContentBytes}; {data.archivedCount}</Typography.Text>
    <Alert type="info" message={text('回滚使用历史 previousThreshold 和新的可信基线生成新 UUID 发布，保留当前其它规则；不会复制整个旧云对象。',
      'Rollback uses the historical previous threshold and a fresh trusted baseline with a new UUID, retaining other current rules; the entire old cloud object is not copied.')} />
    <Table rowKey="publicationId" size="small" dataSource={data.history} pagination={{ pageSize: 10, showSizeChanger: false }} columns={[
      { title: text('可信发布 / 核验时间', 'Trusted publication / verification time'), render: (_, row) => `${row.publicationId} / ${row.verifiedAt}` },
      { title: text('hash', 'Hash'), dataIndex: 'contentHash' },
      { title: text('当前可回滚 / 原因', 'Currently available for rollback / reason'), render: (_, row) => `${row.rollbackAvailable} / ${row.reason ?? '—'}` },
      { title: text('操作', 'Action'), render: (_, row) => <Space><Button disabled={busy} onClick={() => onRead(row.publicationId)}>{text('读原回执', 'Read original receipt')}</Button>
        <Button disabled={busy || !canWrite || !row.rollbackAvailable} onClick={() => onRollback(row.publicationId)}>{text('选择可信阈值回滚', 'Choose trusted threshold rollback')}</Button></Space> },
    ]} />
    <Table<ApigOperation> rowKey="requestId" size="small" dataSource={data.operations} pagination={{ pageSize: 10, showSizeChanger: false }}
      rowSelection={{ selectedRowKeys: selected, preserveSelectedRowKeys: true, hideSelectAll: true,
        getCheckboxProps: row => ({ disabled: busy || !canWrite || !archivable(row) }),
        onChange: keys => { if (!busy) setSelected(keys.map(String)); } }} columns={[
        { title: text('最新详情 UUID', 'Recent detail UUID'), dataIndex: 'requestId' },
        { title: text('状态 / 云写 / 本地阶段', 'Status / cloud write / local stage'), render: (_, row) => `${row.status} / ${row.cloudWrite.status} / ${row.completionState}` },
        { title: text('只读回执', 'Read-only receipt'), render: (_, row) => <Button disabled={busy} onClick={() => onRead(row.requestId)}>{text('读取该原回执', 'Read this original receipt')}</Button> },
      ]} />
    <Typography.Text>{text(`明确选择 ${selected.length} 条；表中是最新最多 50 条详情，列表外历史可填原 UUID 读取并单条归档。`,
      `${selected.length} requests explicitly selected; the table lists at most 50 recent details. Read an older original UUID to archive it individually.`)}</Typography.Text>
    <Popconfirm title={text('明确移除所选回滚正文，保留永久事实？', 'Explicitly remove selected rollback bodies and retain permanent facts?')}
      description={text(`确认数量 ${review?.ids.length ?? selected.length}；使用归档代次 ${review?.generation ?? data.generation}，云配置不变。`,
        `Review ${review?.ids.length ?? selected.length} requests at archive generation ${review?.generation ?? data.generation}; cloud configuration is unchanged.`)}
      okText={text('确认损失所选回滚正文并归档', 'Confirm loss of selected rollback bodies and archive')}
      onOpenChange={open => { if (open) setReview({ ids: [...selected].sort(), generation: data.generation }); }}
      onConfirm={async () => { if (review) await onArchive(review.ids, review.generation); }}>
      <Button disabled={busy || !canWrite || !valid}>{text('明确归档所选 APIG 详情', 'Explicitly archive selected APIG details')}</Button>
    </Popconfirm>
    {selected.length > 0 && <Button disabled={busy} onClick={() => setSelected([])}>{text('明确清空归档选择', 'Explicitly clear archive selections')}</Button>}
  </Space>;
}
