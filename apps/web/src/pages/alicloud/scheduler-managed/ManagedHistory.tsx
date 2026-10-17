import { Alert, Button, Checkbox, Popconfirm, Space, Table, Typography } from 'antd';
import { useState } from 'react';
import type { ManagedController } from './useManagedJobs';
import { useText } from './text';
interface Row { id: string; purpose: 'preview' | 'apply'; label: string; eligible: boolean }
export function ManagedHistory({ flow, canManage }: { flow: ManagedController; canManage: boolean }) {
  const t = useText(), [selected, setSelected] = useState<string[]>([]), [loss, setLoss] = useState(false);
  const [review, setReview] = useState<{ ids: string[]; generation: number } | null>(null), data = flow.data;
  if (!data) return null;
  const rows: Row[] = [...data.previews.map(row => ({ id: row.id, purpose: 'preview' as const, label: row.archived ? 'archived' : row.operationId ? 'claimed' : 'preview', eligible: row.archivable })),
    ...data.operations.map(row => ({ id: row.requestId, purpose: 'apply' as const, label: `${row.status} · ${row.completionState}`, eligible: row.archivable }))];
  const canReview = canManage && data.canManage && !flow.busy && selected.length > 0 && selected.length <= Math.min(48, data.limits.maxArchive)
    && selected.every(id => rows.some(row => row.id === id && row.eligible));
  return <section aria-label={t('受管修改历史与正文归档', 'Managed history and body archive')}><Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{t('受管修改历史与正文归档', 'Managed history and body archive')}</Typography.Title>
    <Typography.Text>{t('台账代次 / 已归档 / 正文字节', 'Ledger generation / archived / body bytes')}: {data.generation} / {data.archivedCount} / {data.storedContentBytes}</Typography.Text>
    <Typography.Text>{t('每类最多显示最新 50 条；更旧原编号可单独 GET。', 'Each class shows at most its latest 50 rows; read an older original ID with GET.')} {data.previews.length}/{data.previewTotal} + {data.operations.length}/{data.operationTotal}</Typography.Text>
    {(data.previewsTruncated || data.operationsTruncated) && <Alert type="info" message={t('列表有界，未显示全部历史；不会无限扫描。', 'The bounded list does not show all history and never scans without a limit.')} />}
    <Table<Row> size="small" rowKey="id" dataSource={rows} pagination={{ pageSize: 50, showSizeChanger: false }} rowSelection={{ selectedRowKeys: selected,
      onChange: keys => setSelected(keys.filter((key): key is string => typeof key === 'string')),
      getCheckboxProps: row => ({ disabled: !canManage || !data.canManage || !row.eligible || flow.busy, 'aria-label': `Archive ${row.id}` }) }} columns={[
        { title: t('原编号', 'Original ID'), dataIndex: 'id' }, { title: t('用途 / 状态', 'Purpose / status'), render: (_, row) => `${row.purpose} · ${row.label}` },
        { title: t('只读读取', 'Read only'), render: (_, row) => <Button disabled={flow.reading} onClick={() => void flow.readOriginal(row.id, row.purpose)}>{t('读取原编号', 'Read original ID')}</Button> },
      ]} />
    <Button disabled={!canReview} onClick={() => { setLoss(false); setReview({ ids: [...selected].sort(), generation: data.generation }); }}>{t('审查所选正文归档', 'Review selected body archive')}</Button>
    {review && <><Alert type="warning" message={t(`归档 ${review.ids.length} 条，使用审查代次 ${review.generation}；失去旧值/新值和预览正文，永久事实保留。`,
      `Archive ${review.ids.length} rows at reviewed generation ${review.generation}; old/new values and preview bodies will be lost, while permanent facts remain.`)} />
      {review.generation !== data.generation && <Alert type="warning" message={t('当前台账代次已变化；本次仍提交原审查代次，冲突保留选择，需重新审查。',
        'The ledger generation changed. This action retains the reviewed generation; a conflict keeps choices and requires a new review.')} />}
      <Checkbox checked={loss} onChange={event => setLoss(event.target.checked)}>{t('确认不可恢复的正文损失与所选数量', 'Confirm irreversible body loss and selected count')}</Checkbox>
      <Popconfirm title={t('明确归档所选终态正文？', 'Explicitly archive these terminal bodies?')} okText={t('确认损失并归档', 'Confirm loss and archive')}
        disabled={!loss || flow.busy || !canManage} onConfirm={() => flow.archive(review.ids, review.generation)}>
        <Button danger disabled={!loss || flow.busy || !canManage}>{t('归档审查中的正文', 'Archive reviewed bodies')}</Button>
      </Popconfirm></>}
    <Alert type="info" message={t('只归档服务端允许的非活动终态或已过期未领取预览，每次最多 48 条。停用来源仍可本地恢复/归档；归档不会停止远端或解锁 Unknown 风险。',
      'Only server-eligible inactive terminal records or expired unclaimed previews can be archived, at most 48. Disabled sources permit local recovery/archive; archive never stops remote work or clears Unknown risk.')} />
  </Space></section>;
}
