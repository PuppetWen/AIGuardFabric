import { Button, Popconfirm, Space, Table, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import type { MseInventory, MseOperation } from '@/types/mseInventory';

export default function MseOperations({ data, selected, onSelected, busy, canWrite, onRead, onArchive }: {
  data: MseInventory; selected: string[]; onSelected: (ids: string[]) => void; busy: boolean; canWrite: boolean;
  onRead: (id: string) => void; onArchive: () => void;
}) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Space direction="vertical" size={8} style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('最近50条盘点回执', 'Recent 50 inventory receipts')}</Typography.Title>
    <Typography.Text type="secondary">{text(`台账代次 ${data.generation}；已归档 ${data.archivedCount}。只选择可归档终态；活动台账上限512条/4MiB。`,
      `Ledger generation ${data.generation}; archived ${data.archivedCount}. Select archivable terminal records only; active capacity 512 records/4 MiB.`)}</Typography.Text>
    <Table<MseOperation> rowKey="requestId" size="small" dataSource={data.operations} pagination={{ pageSize: 50, showSizeChanger: false }}
      rowSelection={canWrite ? { selectedRowKeys: selected, onChange: keys => onSelected(keys.map(String)),
        getCheckboxProps: row => ({ disabled: busy || !row.archivable || row.archived }) } : undefined} columns={[
        { title: text('原请求 UUID', 'Original request UUID'), dataIndex: 'requestId', ellipsis: true },
        { title: text('状态', 'Status'), render: (_, row) => <Space><Tag>{row.status}</Tag>{row.mocked && <Tag color="blue">Mock</Tag>}</Space> },
        { title: text('页 / 服务', 'Pages / services'), render: (_, row) => `${row.pagesRead} / ${row.servicesObserved}` },
        { title: text('曾发布', 'Published historically'), render: (_, row) => row.published ? text('是', 'Yes') : text('否', 'No') },
        { title: text('操作', 'Actions'), render: (_, row) => <Button disabled={busy} onClick={() => onRead(row.requestId)}>{text('读取原回执', 'Read original receipt')}</Button> },
      ]} />
    {canWrite && <Popconfirm title={text(`确认归档所选 ${selected.length} 条终态回执？`, `Archive ${selected.length} selected terminal receipts?`)}
      description={text('仅整理本地台账，保留原编号墓碑和历史发布结果，不改云或资产。并发更新409时先刷新重新选择。',
        'Organize the local ledger only; retain ID tombstones and historical publication. Cloud/assets remain unchanged. On HTTP 409 refresh and select again.')}
      onConfirm={onArchive}><Button disabled={busy || selected.length === 0 || selected.length > 100}>{text('归档所选终态回执', 'Archive selected terminal receipts')}</Button></Popconfirm>}
  </Space>;
}
