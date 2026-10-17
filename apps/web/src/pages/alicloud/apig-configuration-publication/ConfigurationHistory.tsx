import { useState } from 'react';
import { Alert, Button, Popconfirm, Space, Table, Typography } from 'antd';
import type { ConfigurationOperation, ConfigurationState } from '@/types/apigConfigurationPublication';
import { useApigText } from './text';

export default function ConfigurationHistory({ data, canWrite, busy, held, onRead, onRollback, onArchive }: {
  data: ConfigurationState; canWrite: boolean; busy: boolean; held: boolean; onRead: (id: string) => void; onRollback: (id: string) => void;
  onArchive: (ids: string[], generation: number) => Promise<void>;
}) {
  const text = useApigText(), [selected, setSelected] = useState<string[]>([]), [review, setReview] = useState<{ ids: string[]; generation: number } | null>(null);
  const archivable = (row: ConfigurationOperation) => row.archivable && row.allowedActions.includes('archive');
  const valid = selected.length > 0 && selected.length <= data.limits.maxArchive && selected.every(id => data.operations.some(row => row.requestId === id && archivable(row)));
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('配置可信历史、回执与容量归档', 'Trusted configuration history, receipts and capacity archive')}</Typography.Title>
    <Typography.Text>{text('详情条数 / 上限；正文 bytes / 上限；已归档', 'Detailed runs / limit; body bytes / limit; archived')}: {data.detailedRunCount}/{data.limits.maxDetailedRuns}; {data.storedContentBytes}/{data.limits.maxStoredContentBytes}; {data.archivedCount}</Typography.Text>
    <Alert type="info" message={text('回滚把历史公开开关或权重放到新的可信观察基线，生成新 UUID；保留当前私密配置和其它环境。',
      'Rollback applies historical public switches or weights to a fresh trusted observation with a new UUID, retaining current private configuration and other environments.')} />
    <Table rowKey="publicationId" size="small" dataSource={data.history} pagination={{ pageSize: 10, showSizeChanger: false }} columns={[
      { title: text('可信发布 / 核验时间', 'Trusted publication / verification time'), render: (_, row) => `${row.publicationId} / ${row.verifiedAt}` },
      { title: 'Hash', dataIndex: 'contentHash' },
      { title: text('当前可回滚 / 原因', 'Currently available for rollback / reason'), render: (_, row) => `${row.rollbackAvailable} / ${row.reason ?? '—'}` },
      { title: text('操作', 'Action'), render: (_, row) => <Space wrap>
        <Button onClick={() => onRead(row.publicationId)}>{text('读配置原回执', 'Read original configuration receipt')}</Button>
        <Button disabled={busy || held || !canWrite || !row.rollbackAvailable} onClick={() => onRollback(row.publicationId)}>{text('选择可信公开配置回滚', 'Choose trusted public configuration rollback')}</Button>
      </Space> },
    ]} />
    <Table<ConfigurationOperation> rowKey="requestId" size="small" dataSource={data.operations} pagination={{ pageSize: 10, showSizeChanger: false }}
      rowSelection={{ selectedRowKeys: selected, preserveSelectedRowKeys: true, hideSelectAll: true,
        getCheckboxProps: row => ({ disabled: busy || !canWrite || !archivable(row) }), onChange: keys => { if (!busy) setSelected(keys.map(String)); } }} columns={[
        { title: text('最新详情 UUID', 'Recent detail UUID'), dataIndex: 'requestId' },
        { title: text('状态 / 云写 / 本地阶段', 'Status / cloud write / local stage'), render: (_, row) => `${row.status} / ${row.cloudWrite.status} / ${row.completionState}` },
        { title: text('只读回执', 'Read-only receipt'), render: (_, row) => <Button onClick={() => onRead(row.requestId)}>{text('读取该配置原回执', 'Read this original configuration receipt')}</Button> },
      ]} />
    <Typography.Text>{text(`明确选择 ${selected.length} 条；表中是最新最多 50 条详情，历史可填原 UUID 读取并单条归档。`,
      `${selected.length} requests explicitly selected; the table shows at most 50 recent details. Read an older UUID to archive it individually.`)}</Typography.Text>
    <Popconfirm title={text('明确损失所选可信回滚正文，保留永久事实？', 'Explicitly lose selected trusted rollback bodies and retain permanent facts?')}
      description={text(`确认数量 ${review?.ids.length ?? selected.length}；归档代次 ${review?.generation ?? data.generation}，云配置不变。`,
        `Review ${review?.ids.length ?? selected.length} requests at archive generation ${review?.generation ?? data.generation}; cloud configuration is unchanged.`)}
      okText={text('确认损失所选配置回滚正文并归档', 'Confirm loss of selected configuration rollback bodies and archive')}
      onOpenChange={open => { if (open) setReview({ ids: [...selected].sort(), generation: data.generation }); }}
      onConfirm={async () => { if (review) await onArchive(review.ids, review.generation); }}>
      <Button disabled={busy || !canWrite || !valid}>{text('明确归档所选配置详情', 'Explicitly archive selected configuration details')}</Button>
    </Popconfirm>
    {selected.length > 0 && <Button disabled={busy} onClick={() => setSelected([])}>{text('明确清空配置归档选择', 'Explicitly clear configuration archive selections')}</Button>}
  </Space>;
}
