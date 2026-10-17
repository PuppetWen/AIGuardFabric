import { useState } from 'react';
import { Alert, Button, Checkbox, Space, Typography } from 'antd';
import PublicationPolicies from './PublicationPolicies';
import { matchingObservation, unknownAcknowledgementReady } from './eligibility';
import { usePublicationText } from './text';
import type { Baseline } from './usePublication';
import type { Change, Operation, PolicyRevision, PublicationState } from './types';
export default function PublicationCandidate({ data, baseline, operation, selected, onSelected, rollbackId, onPublishMode,
  canWrite, busy, onPrepare, onRead }: {
  data: PublicationState; baseline: Baseline | null; operation: Operation | null; selected: PolicyRevision[];
  onSelected: (rows: PolicyRevision[]) => void; rollbackId: string | null; onPublishMode: () => void;
  canWrite: boolean; busy: boolean; onPrepare: (change: Change, acknowledge: boolean) => void; onRead: (id: string) => void;
}) {
  const text = usePublicationText(), [acknowledge, setAcknowledge] = useState(false);
  const unresolved = operation?.requestId === data.unresolvedOperationId ? operation
    : data.operations.find(row => row.requestId === data.unresolvedOperationId) ?? null;
  const unknownReady = unknownAcknowledgementReady(data, baseline?.observation ?? null, unresolved);
  const history = data.history.find(row => row.publicationId === rollbackId);
  const validChange = rollbackId ? !!history?.rollbackAvailable && history.target.targetScopeId === data.binding?.targetScopeId
    : selected.length > 0 && selected.length <= data.limits.maxPolicies;
  const ready = canWrite && !busy && !data.busy && data.canPrepare && !!baseline
    && matchingObservation(data, baseline.observation) && validChange
    && (!data.unresolvedOperationId || (unknownReady && acknowledge));
  const prepare = () => {
    if (!ready) return;
    const change: Change = rollbackId ? { action: 'rollback', publication_id: rollbackId }
      : { action: 'publish', policies: selected.map(row => ({ policy_id: row.policyId, version: row.version })).sort((a, b) => a.policy_id.localeCompare(b.policy_id)) };
    onPrepare(change, acknowledge);
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    {rollbackId ? <><Alert type="info" message={text('正在准备可信历史回滚的新发布。原正文由服务端读取，不接受浏览器正文。', 'Preparing a new publication from trusted rollback history. The server reads its original content; browser-supplied content is not accepted.')} />
      <Typography.Text>{text('可信历史来源', 'Trusted historical source')}: {rollbackId}</Typography.Text>
      <Button disabled={busy} onClick={onPublishMode}>{text('返回当前政策新发布', 'Return to publication of current policies')}</Button></>
      : <PublicationPolicies selected={selected} onSelected={onSelected} maximum={data.limits.maxPolicies} disabled={busy || !canWrite} />}
    {data.unresolvedOperationId && <><Alert type="warning" showIcon message={text('存在未知旧写，不能安全重试。先明确本地恢复未完成的旧事实；旧租约到期后再重新观察，并明确接受旧远端请求可能迟到的风险。', 'An unknown old write prevents a safe retry. Explicitly recover its incomplete local fact first; after its lease expires obtain a fresh observation and accept that the old remote request may finish late.')}
      description={`${data.unresolvedOperationId} / ${unresolved?.leaseExpiresAt ?? text('需读取原回执核对租约', 'Read the original receipt to inspect its lease')}`} />
      <Button onClick={() => onRead(data.unresolvedOperationId!)}>{text('读取未知旧写的原回执', 'Read the unknown old write receipt')}</Button>
      <Checkbox checked={acknowledge} disabled={busy || !unknownReady} onChange={event => setAcknowledge(event.target.checked)}>{text('明确承认这个未知原编号；新发布可能与旧写重叠', 'Acknowledge this unknown original ID; a new publication may overlap with the old write')}</Checkbox>
      {!unknownReady && <Typography.Text type="warning">{text('旧事实须已完成本地终态；新观察的开始与完成时间都必须晚于原租约到期。', 'The old fact must have local completion; the new observation must both start and finish after its original lease expires.')}</Typography.Text>}</>}
    <Button type="primary" disabled={!ready} loading={busy} onClick={prepare}>{text('生成可信预览（不写云）', 'Prepare trusted preview (no cloud write)')}</Button>
  </Space>;
}
