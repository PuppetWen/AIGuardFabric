import { useState } from 'react';
import { Alert, Button, Checkbox, Descriptions, Popconfirm, Space, Typography } from 'antd';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import type { ConfigurationOperation, ConfigurationState } from '@/types/apigConfigurationPublication';
import { observable } from './eligibility';
import { useApigText } from './text';

export default function ConfigurationReceipt({ operation: row, data, canWrite, busy, onObserve, onRecover, onArchive }: {
  operation: ConfigurationOperation; data: ConfigurationState | null; canWrite: boolean; busy: boolean;
  onObserve: (live: boolean) => void; onRecover: () => void; onArchive: (id: string, generation: number) => Promise<void>;
}) {
  const text = useApigText(), scope = useOperationScope(), [live, setLive] = useState(false);
  const [copyStatus, setCopyStatus] = useState(''), [copyBusy, setCopyBusy] = useState(false), [archiveGeneration, setArchiveGeneration] = useState<number | null>(null);
  const copy = async () => {
    const generation = scope.begin(); if (generation === undefined) return;
    setCopyBusy(true); setCopyStatus('');
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(row.requestId);
      if (scope.current(generation)) setCopyStatus(text('已复制原配置请求 UUID', 'Original configuration request UUID copied'));
    } catch { if (scope.current(generation)) setCopyStatus(text('复制失败；请手动选择显示的 UUID。', 'Copy failed; select the displayed UUID manually.')); }
    finally { if (scope.finish(generation)) setCopyBusy(false); }
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('原 APIG 配置请求回执', 'Original APIG configuration request receipt')}</Typography.Title>
    <Typography.Text code>{row.requestId}</Typography.Text>
    <Button disabled={copyBusy} onClick={() => void copy()}>{text('复制原配置请求 UUID', 'Copy original configuration request UUID')}</Button>
    {copyStatus && <Typography.Text role="status">{copyStatus}</Typography.Text>}
    <Descriptions size="small" bordered column={2} items={[
      { key: 'status', label: text('原结果 / 详情状态', 'Original outcome / detail status'), children: `${row.originalStatus ?? row.status} / ${row.status}` },
      { key: 'source', label: text('原写入来源 / 版本', 'Original write source / revision'), children: `${row.target.sourceLabel} / v${row.target.configurationVersion}` },
      { key: 'current', label: text('来源仍当前', 'Source still current'), children: row.sourceCurrent === null ? text('未知', 'Unknown') : String(row.sourceCurrent) },
      { key: 'cloud', label: text('云写入阶段', 'Cloud write stage'), children: `${row.cloudWrite.status} / ${row.cloudWrite.providerRequestId ?? '—'}` },
      { key: 'read', label: text('独立配置回读', 'Separate configuration readback'), children: `${row.readback.status} / ${row.readback.currentHash ?? '—'}` },
      { key: 'local', label: text('本地终态与审计', 'Local terminal fact and audit'), children: `${row.localPublication.status} / ${row.completionState}` },
      { key: 'deployment', label: text('云部署', 'Cloud deployment'), children: text('未知；按云控制台实际 Publish/Apply 流程核查', 'Unknown; inspect the actual cloud-console Publish/Apply workflow') },
      { key: 'consumer', label: text('消费者加载', 'Consumer loading'), children: text('未知；须独立验证实际业务', 'Unknown; verify the actual workload independently') },
    ]} />
    {(row.cloudWrite.status === 'unknown' || row.status === 'uncertain' || row.completionState !== 'complete') && <Alert type="warning" message={text('Unknown 或未完成本地审计不能显示成功；不重发原云写。',
      'Unknown or incomplete local audit is not success; the original cloud write is never resent.')} />}
    {row.safeReason && <Alert type="info" message={row.safeReason} />}
    <Popconfirm title={text('仅恢复原本地终态和审计，不调用云？', 'Recover only the original local terminal fact and audit, without calling the cloud?')}
      okText={text('确认纯本地恢复', 'Confirm local-only recovery')} onConfirm={onRecover}>
      <Button disabled={busy || !canWrite || !row.allowedActions.includes('recover_local')}>{text('明确恢复本地配置回执', 'Explicitly recover the local configuration receipt')}</Button>
    </Popconfirm>
    {data?.binding?.transportMode === 'live' && <Checkbox checked={live} disabled={busy} onChange={e => setLive(e.target.checked)}>
      {text('确认只读核查原操作对应的当前 Live 目标', 'Confirm read-only inspection of the current Live target for the original operation')}</Checkbox>}
    <Button disabled={busy || !observable(data, row) || (data?.binding?.transportMode === 'live' && !live)} onClick={() => onObserve(live)}>
      {text('明确独立观察原配置目标（不改原写入结论）', 'Explicitly observe the original configuration target (original write outcome is retained)')}</Button>
    <Popconfirm title={text('归档移除此条可信回滚正文，保留永久事实；云配置不变。', 'Archive removes this trusted rollback body and retains the permanent fact; cloud configuration is unchanged.')}
      okText={text('确认归档这 1 条配置详情', 'Confirm archiving this 1 configuration detail')}
      onOpenChange={open => { if (open && data) setArchiveGeneration(data.generation); }}
      onConfirm={async () => { if (archiveGeneration !== null && scope.current()) await onArchive(row.requestId, archiveGeneration); }}>
      <Button disabled={busy || !canWrite || !data || !row.archivable || !row.allowedActions.includes('archive')}>
        {text('明确归档原配置详情（1 条）', 'Explicitly archive original configuration detail (1 request)')}</Button>
    </Popconfirm>
  </Space>;
}
