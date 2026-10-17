import { useState } from 'react';
import { Alert, Button, Popconfirm, Space, Table, Typography } from 'antd';
import { revisionLabel, usePublicationText } from './text';
import type { Operation, PublicationHistory as History, PublicationState } from './types';
export default function PublicationHistory({ data, canWrite, busy, onRollback, onRead, onArchive }: {
  data: PublicationState; canWrite: boolean; busy: boolean;
  onRollback: (id: string) => void; onRead: (id: string) => void; onArchive: (ids: string[], generation: number) => void;
}) {
  const text = usePublicationText(), [selected, setSelected] = useState<string[]>([]);
  const [reviewed, setReviewed] = useState<{ ids: string[]; generation: number } | null>(null);
  const eligible = (row: Operation) => row.archivable && row.allowedActions.includes('archive');
  const ids = selected.filter(id => data.operations.some(row => row.requestId === id && eligible(row)));
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('可信回滚历史', 'Trusted rollback history')}</Typography.Title>
    <Table<History> size="small" rowKey="publicationId" dataSource={data.history} pagination={{ pageSize: 50, showSizeChanger: false }} columns={[
      { title: text('发布编号 / 时间', 'Publication ID / time'), render: (_, row) => <>{row.publicationId}<br />{row.verifiedAt}</> },
      { title: text('SHA256 / 字节', 'SHA256 / bytes'), render: (_, row) => `${row.contentHash} / ${row.contentBytes}` },
      { title: text('原政策版本', 'Original policy revisions'), render: (_, row) => revisionLabel(row.sourcePolicyVersions) },
      { title: text('操作', 'Action'), render: (_, row) => <Space direction="vertical">
        <Button disabled={busy || !canWrite || !data.canPrepare || !row.rollbackAvailable || row.target.targetScopeId !== data.binding?.targetScopeId}
          onClick={() => onRollback(row.publicationId)}>{text('选择可信来源准备新回滚', 'Select trusted source for a new rollback')}</Button>
        {row.reason && <Typography.Text type="secondary">{row.reason}</Typography.Text>}
      </Space> },
    ]} />
    <Typography.Title level={5}>{text('最近操作与明确归档', 'Recent operations and explicit archive')}</Typography.Title>
    <Alert type="info" message={text('归档释放详细记录和正文容量，停用连接后仍可执行；永久原编号与未知风险事实保留。', 'Archive frees detailed records and content capacity, including after disabling the connection. Permanent original IDs and unknown-risk facts remain.')}
      description={`${text('详细记录', 'Detailed runs')} ${data.detailedRunCount}/${data.limits.maxDetailedRuns}; ${text('正文字节', 'Content bytes')} ${data.storedContentBytes}/${data.limits.maxStoredContentBytes}; ${text('累计归档', 'Archived total')} ${data.archivedCount}`} />
    <Table<Operation> size="small" rowKey="requestId" dataSource={data.operations} pagination={{ pageSize: 50, showSizeChanger: false }}
      rowSelection={{ selectedRowKeys: ids, getCheckboxProps: row => ({ disabled: !canWrite || busy || !eligible(row) }),
        onChange: keys => { if (!busy && canWrite) setSelected(keys.map(String)); } }} columns={[
        { title: text('原请求编号', 'Original request ID'), dataIndex: 'requestId', render: (id: string) => <Button type="link" onClick={() => onRead(id)}>{id}</Button> },
        { title: text('状态 / 本地完成', 'Status / local completion'), render: (_, row) => `${row.status} / ${row.completionState}` },
        { title: text('原配置版本 / 模式', 'Original configuration version / mode'), render: (_, row) => `${row.target.configurationVersion} / ${row.target.transportMode}` },
      ]} />
    <Popconfirm onOpenChange={open => { if (open) setReviewed({ ids: [...ids], generation: data.generation }); }}
      title={text(`明确归档 ${reviewed?.ids.length ?? ids.length} 条？将失去这些记录的回滚正文，不改变当前云内容；原编号永不重派。`,
      `Archive ${reviewed?.ids.length ?? ids.length} records explicitly? Their rollback content will be lost. Current cloud content is unchanged and original IDs are never redispatched.`)}
      okText={text('确认移除所选回滚正文', 'Confirm removing selected rollback content')}
      onConfirm={() => { if (canWrite && !busy && reviewed && reviewed.ids.length > 0 && reviewed.ids.length <= data.limits.maxArchive) onArchive(reviewed.ids, reviewed.generation); }}>
      <Button disabled={!canWrite || busy || ids.length === 0 || ids.length > data.limits.maxArchive}>{text(`明确归档所选 ${ids.length} 条`, `Archive ${ids.length} selected records explicitly`)}</Button>
    </Popconfirm>
  </Space>;
}
