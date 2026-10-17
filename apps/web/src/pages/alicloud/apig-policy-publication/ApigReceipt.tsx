import { useState } from 'react';
import { Alert, Button, Checkbox, Descriptions, Popconfirm, Space, Typography } from 'antd';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import type { ApigOperation, ApigPublicationState } from '@/types/apigPolicyPublication';
import { originalObservable } from './eligibility';
import { revisions, useApigText } from './text';

export default function ApigReceipt({ operation: row, data, canWrite, busy, onObserve, onRecover, onArchive }: {
  operation: ApigOperation; data: ApigPublicationState | null; canWrite: boolean; busy: boolean;
  onObserve: (live: boolean) => void; onRecover: () => void; onArchive: (id: string, generation: number) => Promise<void>;
}) {
  const text = useApigText(), scope = useOperationScope();
  const [live, setLive] = useState(false), [copyStatus, setCopyStatus] = useState(''), [copyBusy, setCopyBusy] = useState(false);
  const [archiveGeneration, setArchiveGeneration] = useState<number | null>(null);
  const copy = async () => {
    const generation = scope.begin(); if (generation === undefined) return;
    setCopyBusy(true); setCopyStatus('');
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(row.requestId);
      if (scope.current(generation)) setCopyStatus(text('已复制原 APIG 请求 UUID', 'Original APIG request UUID copied'));
    } catch { if (scope.current(generation)) setCopyStatus(text('复制失败；请手动选择显示的 UUID。', 'Copy failed; select the displayed UUID manually.')); }
    finally { if (scope.finish(generation)) setCopyBusy(false); }
  };
  const canArchive = canWrite && row.archivable && row.allowedActions.includes('archive') && !!data;
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('原 APIG 请求回执', 'Original APIG request receipt')}</Typography.Title>
    <Typography.Text code>{row.requestId}</Typography.Text>
    <Button disabled={copyBusy} onClick={() => void copy()}>{text('复制原 APIG 请求 UUID', 'Copy original APIG request UUID')}</Button>
    {copyStatus && <Typography.Text role="status">{copyStatus}</Typography.Text>}
    <Descriptions size="small" bordered column={2} items={[
      { key: 'status', label: text('原结果 / 详情状态', 'Original outcome / detail status'), children: `${row.originalStatus ?? row.status} / ${row.status}` },
      { key: 'source', label: text('原写入来源 / 版本', 'Original write source / revision'), children: `${row.target.sourceLabel} / v${row.target.configurationVersion}` },
      { key: 'versions', label: text('原平台来源版本', 'Original platform source revisions'), children: revisions(row.sourcePolicyVersions) },
      { key: 'current', label: text('来源仍当前 / 当前版本', 'Source still current / current revisions'), children: `${row.sourceCurrent === null ? text('未知', 'Unknown') : row.sourceCurrent} / ${revisions(row.currentPolicyVersions)}` },
      { key: 'cloud', label: text('云写入阶段', 'Cloud write stage'), children: `${row.cloudWrite.status} / ${row.cloudWrite.providerRequestId ?? '—'}` },
      { key: 'read', label: text('独立配置回读', 'Separate configuration readback'), children: `${row.readback.status} / ${row.readback.currentHash ?? '—'}` },
      { key: 'local', label: text('本地终态与审计', 'Local terminal fact and audit'), children: `${row.localPublication.status} / ${row.completionState}` },
      { key: 'consumer', label: text('消费者加载', 'Consumer loading'), children: text('未知，没有消费者回执', 'Unknown: no consumer receipt') },
    ]} />
    {(row.cloudWrite.status === 'unknown' || row.status === 'uncertain' || row.completionState !== 'complete') && <Alert type="warning" message={text('Unknown 或未完成本地发布不能显示成功；不重发原云写。',
      'Unknown or incomplete local publication is not success; the original cloud write is never resent.')} />}
    {row.safeReason && <Alert type="info" message={row.safeReason} />}
    <Popconfirm title={text('只恢复本地终态与审计，不调用云？', 'Recover only the local terminal fact and audit, without calling the cloud?')}
      okText={text('确认纯本地恢复', 'Confirm local-only recovery')} onConfirm={onRecover}>
      <Button disabled={busy || !canWrite || !row.allowedActions.includes('recover_local')}>{text('明确恢复本地 APIG 回执', 'Explicitly recover the local APIG receipt')}</Button>
    </Popconfirm>
    {data?.binding?.transportMode === 'live' && <Checkbox checked={live} disabled={busy} onChange={event => setLive(event.target.checked)}>
      {text('确认只读核查原操作对应的当前 Live 目标', 'Confirm read-only inspection of the current Live target for the original operation')}</Checkbox>}
    <Button disabled={busy || !originalObservable(data, row) || (data?.binding?.transportMode === 'live' && !live)} onClick={() => onObserve(live)}>
      {text('明确独立观察原目标（不改原写入结论）', 'Explicitly observe the original target separately (original write outcome is retained)')}</Button>
    <Popconfirm title={text('归档将失去此条可信回滚正文，保留永久事实；云配置不变。', 'Archive removes this trusted rollback body and retains the permanent fact; cloud configuration is unchanged.')}
      okText={text('确认归档这 1 条', 'Confirm archiving this 1 request')} onOpenChange={open => { if (open && data) setArchiveGeneration(data.generation); }}
      onConfirm={async () => { if (archiveGeneration !== null && scope.current()) await onArchive(row.requestId, archiveGeneration); }}>
      <Button disabled={busy || !canArchive}>{text('明确归档原 APIG 详情（1 条）', 'Explicitly archive original APIG detail (1 request)')}</Button>
    </Popconfirm>
  </Space>;
}
