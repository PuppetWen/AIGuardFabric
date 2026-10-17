import { useState } from 'react';
import { Alert, Button, Checkbox, Space, Typography } from 'antd';
import type { ApigChange, ApigOperation, ApigPublicationState, PolicyRevision } from '@/types/apigPolicyPublication';
import type { Baseline } from './useApigPublication';
import ApigSources from './ApigSources';
import { matchingObservation, unknownReady } from './eligibility';
import { useApigText } from './text';

export default function ApigCandidate({ data, baseline, operation, selected, onSelect, rollbackId, onPublishMode,
  canWrite, busy, loading, eligibleOnly, onSourcePage, onPrepare, onRead }: {
  data: ApigPublicationState; baseline: Baseline | null; operation: ApigOperation | null; selected: PolicyRevision | null;
  onSelect: (row: PolicyRevision | null) => void; rollbackId: string | null; onPublishMode: () => void; canWrite: boolean;
  busy: boolean; loading: boolean; eligibleOnly: boolean; onSourcePage: (page: number, only: boolean) => void;
  onPrepare: (change: ApigChange, acknowledge: boolean) => void; onRead: (id: string) => void;
}) {
  const text = useApigText(), [acknowledge, setAcknowledge] = useState(false);
  const unresolved = operation?.requestId === data.unresolvedOperationId ? operation : data.operations.find(row => row.requestId === data.unresolvedOperationId) ?? null;
  const source = selected ? data.sources.items.find(row => row.policyId === selected.policyId) : undefined;
  const validSource = !!selected && (!source || (source.eligible && source.version === selected.version));
  const rollback = rollbackId ? data.history.find(row => row.publicationId === rollbackId && row.rollbackAvailable) : undefined;
  const unknownAllowed = unknownReady(data, baseline?.observation ?? null, unresolved);
  const ready = canWrite && !busy && !data.busy && data.canPrepare && !!baseline && matchingObservation(data, baseline.observation)
    && (rollbackId ? !!rollback : validSource) && (!data.unresolvedOperationId || (acknowledge && unknownAllowed));
  return <Space direction="vertical" style={{ width: '100%' }}>
    {rollbackId ? <>
      <Typography.Text>{text('保留所选可信阈值回滚来源', 'Retained trusted threshold rollback source')}: {rollbackId}</Typography.Text>
      {!rollback && <Alert type="warning" message={text('当前模式/来源不支持该历史回滚，或正文已归档。选择保留，但不能生成预览。',
        'The current mode/source does not support this history, or its body was archived. The selection remains, but a preview cannot be prepared.')} />}
      <Button disabled={busy} onClick={onPublishMode}>{text('明确切回当前平台来源发布', 'Explicitly switch back to current platform-source publication')}</Button>
    </> : <ApigSources data={data} selected={selected} onSelect={onSelect} disabled={busy || !canWrite}
      loading={loading} eligibleOnly={eligibleOnly} onPage={onSourcePage} />}
    {data.unresolvedOperationId && <>
      <Alert type="warning" message={text('此独立策略仍有 Unknown 写入风险，旧请求不会因关闭页面、换配置或新 UUID 被取消。',
        'This independent policy has unresolved Unknown write risk. Closing the page, changing configuration or creating a new UUID does not cancel the old request.')}
        description={text('先读原回执，必要时只恢复本地终态；租约过后再明确新观察，观察开始与结束都须晚于旧租约。随后确认旧编号并创建独立新意图，不能称安全重试。',
          'Read the original receipt and recover only its local terminal fact if needed. After the lease, explicitly observe again; both observation start and finish must be later than the old lease. Acknowledge the old ID and create a separate new intent; this is not a guaranteed safe retry.')} />
      <Button disabled={busy} onClick={() => onRead(data.unresolvedOperationId!)}>{text('读取未解决原 APIG 回执（GET）', 'Read unresolved original APIG receipt (GET)')}</Button>
      <Checkbox checked={acknowledge} disabled={busy || !canWrite || !unknownAllowed} onChange={event => setAcknowledge(event.target.checked)}>
        {text(`确认新意图承认旧 Unknown 编号 ${data.unresolvedOperationId}`, `Acknowledge old Unknown ID ${data.unresolvedOperationId} for this new intent`)}</Checkbox>
    </>}
    <Button disabled={!ready} onClick={() => onPrepare(rollbackId ? { action: 'rollback', publication_id: rollbackId }
      : { action: 'publish', policies: [{ policy_id: selected!.policyId, version: selected!.version }] }, acknowledge)}>
      {text('生成可信 APIG 预览（不发云写）', 'Prepare trusted APIG preview (no cloud write)')}</Button>
  </Space>;
}
