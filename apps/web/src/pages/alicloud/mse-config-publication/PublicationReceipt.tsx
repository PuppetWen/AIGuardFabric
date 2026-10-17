import { useState } from 'react';
import { Alert, Button, Checkbox, Descriptions, Popconfirm, Space, Tag } from 'antd';
import { originalObservable } from './eligibility';
import { revisionLabel, usePublicationText } from './text';
import type { Operation, PublicationState } from './types';
export default function PublicationReceipt({ operation, data, canRead, canWrite, busy, onObserve, onRecover }: {
  operation: Operation; data: PublicationState | null; canRead: boolean; canWrite: boolean; busy: boolean;
  onObserve: (confirmLive: boolean) => void; onRecover: () => void;
}) {
  const text = usePublicationText(), [live, setLive] = useState(false);
  const success = operation.status === 'verified' && operation.completionState === 'complete'
    && operation.cloudWrite.status === 'accepted' && operation.readback.status === 'matched' && operation.localPublication.status === 'published';
  const canObserve = canRead && originalObservable(data, operation);
  const liveTarget = data?.binding?.transportMode === 'live';
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Tag color={success ? 'green' : operation.status === 'conflict' || operation.status === 'failed' ? 'red' : 'orange'}>{operation.status}</Tag>
    <Descriptions title={text('原请求回执', 'Original request receipt')} size="small" column={2} items={[
      { key: 'id', label: text('原请求 UUID', 'Original request UUID'), children: operation.requestId },
      { key: 'target', label: text('原目标 / 配置版本', 'Original target / configuration version'), children: `${operation.target.targetScopeId} / ${operation.target.configurationVersion}` },
      { key: 'tuple', label: 'Origin / Namespace / Group / Data ID', children: `${operation.target.engineOrigin} / ${operation.target.namespaceId === '' ? '(default)' : operation.target.namespaceId} / ${operation.target.group} / ${operation.target.dataId}` },
      { key: 'mode', label: text('原模式 / 来源', 'Original mode / source'), children: `${operation.target.transportMode} / ${operation.target.sourceLabel}` },
      { key: 'write', label: text('云写阶段', 'Cloud write stage'), children: operation.cloudWrite.status },
      { key: 'readback', label: text('回读阶段', 'Readback stage'), children: operation.readback.status },
      { key: 'local', label: text('本地发布 / 完成阶段', 'Local publication / completion'), children: `${operation.localPublication.status} / ${operation.completionState}` },
      { key: 'current', label: text('原来源仍为当前版本', 'Original source is still current'), children: operation.sourceCurrent === null ? text('未知', 'Unknown') : operation.sourceCurrent ? text('是', 'Yes') : text('否（原回执来源保持）', 'No (original receipt source retained)') },
      { key: 'versions', label: text('当前政策版本', 'Current policy revisions'), children: revisionLabel(operation.currentPolicyVersions) },
      { key: 'consumer', label: text('消费者已加载', 'Consumer applied'), children: text('未知：没有消费者回执', 'Unknown: no consumer receipt') },
      { key: 'lease', label: text('原写租约到期', 'Original write lease expires'), children: operation.leaseExpiresAt },
      { key: 'archived', label: text('归档 / 原终态', 'Archived / original terminal status'), children: `${operation.archived} / ${operation.originalStatus ?? '—'}` },
    ]} />
    {operation.safeReason && <Alert type="warning" message={operation.safeReason} />}
    {operation.cloudWrite.status === 'unknown' && <Alert type="warning" showIcon message={text('本次云写结果未知；即使当前回读匹配，也不能证明本次写被接受。不得盲重发。', 'This cloud write has an unknown outcome. Even a matching current readback cannot prove it was accepted. Do not resend blindly.')} />}
    {operation.completionState === 'pending_audit' && <Alert type="warning" showIcon message={text('已暂存云端证据，本地审计提交尚未完成；明确恢复只提交本地终态，不调用云端。', 'Cloud evidence is staged; local audit commit is incomplete. Explicit recovery commits only the local terminal state without calling the cloud.')} />}
    {operation.completionState === 'running' && operation.allowedActions.includes('recover_local') && <Alert type="warning" showIcon
      message={text('原租约已过期，本地事实仍未完成。明确恢复仅记录固定未知终态与审计，不发云请求；先完成旧事实再准备独立新观察。', 'The original lease expired while the local fact remained incomplete. Explicit recovery records only an unknown terminal state and audit without a cloud request; complete the old fact before preparing an independent new observation.')} />}
    {canObserve && liveTarget && <Checkbox checked={live} disabled={busy} onChange={event => setLive(event.target.checked)}>{text('确认真实只读观察原目标', 'Confirm a live read-only observation of the original target')}</Checkbox>}
    <Space wrap><Button disabled={busy || !canObserve || (!!liveTarget && !live)} onClick={() => onObserve(live)}>{text('明确观察原目标（不重写）', 'Explicitly observe original target (no rewrite)')}</Button>
      <Popconfirm title={text('仅恢复原回执的本地终态和审计，不发送云请求？', 'Recover only the original local terminal state and audit, without a cloud request?')}
        okText={text('确认本地恢复', 'Confirm local recovery')} onConfirm={onRecover}>
        <Button disabled={busy || !canWrite || !operation.allowedActions.includes('recover_local')}>{text('明确本地恢复', 'Explicit local recovery')}</Button>
      </Popconfirm></Space>
  </Space>;
}
