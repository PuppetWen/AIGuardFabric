import { useRef } from 'react';
import { Alert, Button, List, Popconfirm, Space } from 'antd';
import type { MultiRun } from '@/api/redteamMultiTarget';
import type { useMultiTarget } from './useMultiTarget';
export function RecentRuns({ model, canExecute, zh }: { model: ReturnType<typeof useMultiTarget>; canExecute: boolean; zh: boolean }) {
  const reviewed = useRef<MultiRun | null>(null);
  const text = (en: string, cn: string) => zh ? cn : en;
  const receipt = model.receipt;
  const archivable = receipt?.completionState === 'complete' && receipt.status !== 'archived' && receipt.requestId === model.requestId;
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Button loading={model.readBusy} onClick={() => void model.recentRuns()}>{text('Read my recent UUIDs', '读取我的近期 UUID')}</Button>
    {model.recent && <><List dataSource={model.recent.items} renderItem={row => <List.Item>
      <Button type="link" onClick={() => void model.readOriginal(row.requestId)}>{row.requestId} · {row.status} · g{row.generation}</Button>
    </List.Item>} />
      <Space><Button disabled={model.recent.offset === 0 || model.readBusy} onClick={() => void model.recentRuns(Math.max(0, model.recent!.offset - 20))}>{text('Previous', '上一页')}</Button>
        <Button disabled={model.recent.offset + model.recent.items.length >= model.recent.total || model.readBusy} onClick={() => void model.recentRuns(model.recent!.offset + 20)}>{text('Next', '下一页')}</Button></Space></>}
    {canExecute && <Popconfirm title={text('Archive this reviewed evidence body? Original UUID and terminal audit remain permanent.', '归档已核对的证据正文？原 UUID 与终态审计永久保留。')}
      onOpenChange={open => { if (open) reviewed.current = receipt ? { ...receipt } : null; }}
      onConfirm={() => reviewed.current ? model.archive(reviewed.current) : Promise.resolve()}>
      <Button disabled={!archivable || model.localBusy || model.busy}>{text('Archive reviewed run', '归档已核对战役')}</Button>
    </Popconfirm>}
    <Alert type="info" message={text('128 retained bodies · 256 recent owner UUIDs · 16,384 permanent UUIDs per tenant', '128 条保留正文 · 256 个当前主体近期 UUID · 每租户 16,384 个永久 UUID')}
      description={text('Archive completed bodies to free body capacity. It cannot free permanent UUID capacity or authorize resend. Older UUIDs remain readable by exact ID. Keep original UUIDs outside the recent window.', '归档已完成正文可释放正文容量，不能释放永久 UUID 容量或授权重发。近期窗口以外仍可准确读取原 UUID，请自行保存。')} />
  </Space>;
}
