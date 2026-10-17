import { useEffect, useState } from 'react';
import { Alert, Button, Checkbox, Descriptions, Space } from 'antd';
import { applicable } from './eligibility';
import PublicationTarget from './PublicationTarget';
import { revisionLabel, usePublicationText } from './text';
import type { ApplyInput, Preview, PublicationState } from './types';
export default function PublicationPreview({ preview, data, attempted, canWrite, busy, onApply, onRead }: {
  preview: Preview; data: PublicationState; attempted: string | null; canWrite: boolean; busy: boolean;
  onApply: (input: Pick<ApplyInput, 'confirm_apply' | 'confirm_upsert' | 'confirm_live' | 'confirm_unknown_overlap'>) => void;
  onRead?: (id: string) => void;
}) {
  const text = usePublicationText(), [now, setNow] = useState(Date.now);
  const [apply, setApply] = useState(false), [upsert, setUpsert] = useState(false), [live, setLive] = useState(false), [overlap, setOverlap] = useState(false);
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer); }, []);
  const liveTarget = preview.target.transportMode === 'live';
  const ready = canWrite && !busy && applicable(data, preview, attempted, now) && apply && upsert && (!liveTarget || live) && (!preview.unknownOverlapWarning || overlap);
  return <Space direction="vertical" style={{ width: '100%' }}>
    <PublicationTarget target={preview.target} />
    <Descriptions title={text('可信预览（尚未发送云写）', 'Trusted preview (no cloud write sent)')} size="small" column={2} items={[
      { key: 'id', label: text('预览 / 状态版本', 'Preview / state revision'), children: `${preview.id} / ${preview.stateVersion}` },
      { key: 'expiry', label: text('预览到期', 'Preview expires'), children: preview.expiresAt },
      { key: 'action', label: text('动作 / 历史来源', 'Action / historical source'), children: `${preview.action} / ${preview.sourcePublicationId ?? '—'}` },
      { key: 'claimed', label: text('已领取原编号', 'Claimed original request'), children: preview.consumedBy ?? '—' },
      { key: 'source', label: text('原包政策版本', 'Source bundle revisions'), children: revisionLabel(preview.sourcePolicyVersions) },
      { key: 'current', label: text('预览检查的当前政策版本', 'Current revisions checked by preview'), children: revisionLabel(preview.currentPolicyVersions) },
      { key: 'md5', label: 'Baseline Content MD5', children: preview.baselineMd5 },
      { key: 'baseline', label: text('云基线 SHA256 / 字节', 'Cloud baseline SHA256 / bytes'), children: `${preview.baselineHash} / ${preview.baselineBytes}` },
      { key: 'desired', label: text('期望包 SHA256 / 字节', 'Desired bundle SHA256 / bytes'), children: `${preview.desiredHash} / ${preview.desiredBytes}` },
    ]} />
    <Alert type="warning" showIcon message={text('Content-MD5 upsert 仅保护内容基线，不保证配置仍存在，也不证明消费者已加载。', 'Content-MD5 upsert protects the content baseline; it does not guarantee continued existence or consumer loading.')}
      description={text('此处只比较字节、摘要和可信来源版本，不展示云端原始正文。回滚是新发布，不降平台注册表版本。', 'Comparison exposes bytes, hashes and trusted source revisions, without raw cloud content. Rollback is a new publication and does not lower platform registry versions.')} />
    {preview.reason && <Alert type="warning" message={preview.reason} />}
    {(now >= Date.parse(preview.expiresAt) || attempted === preview.id || !!preview.consumedBy) && <Alert type="warning"
      message={text('此预览已到期或已经尝试领取。先读取原回执，再明确新观察、新预览；不重发原云写。', 'This preview has expired or an attempt to claim it was made. Read the original receipt, then explicitly obtain a new observation and preview; never resend the original cloud write.')} />}
    {preview.consumedBy && <Button disabled={!onRead || !preview.allowedActions.includes('read_receipt')}
      onClick={() => onRead?.(preview.consumedBy!)}>{text('读取此预览的领取回执', 'Read the receipt that claimed this preview')}</Button>}
    <Checkbox checked={apply} disabled={busy} onChange={event => setApply(event.target.checked)}>{text('确认上述目标、来源版本和内容摘要', 'Confirm the target, source revisions and content hashes above')}</Checkbox>
    <Checkbox checked={upsert} disabled={busy} onChange={event => setUpsert(event.target.checked)}>{text('确认 MD5 upsert 可能重建已删除的专用 Data ID', 'Confirm MD5 upsert may recreate the deleted dedicated Data ID')}</Checkbox>
    {liveTarget && <Checkbox checked={live} disabled={busy} onChange={event => setLive(event.target.checked)}>{text('确认发送此目标的真实云写', 'Confirm a live cloud write to this target')}</Checkbox>}
    {preview.unknownOverlapWarning && <><Alert type="warning" message={text('旧远端请求可能迟到完成。当前匹配不证明旧写已停止；这是独立的新业务写，存在覆盖竞态。', 'The old remote request may finish late. A current match does not prove it stopped; this is an independent new business write with overwrite risk.')} />
      <Checkbox checked={overlap} disabled={busy} onChange={event => setOverlap(event.target.checked)}>{text('接受未知旧写与新写可能重叠的风险', 'Accept the risk of overlap between the unknown old write and the new write')}</Checkbox></>}
    <Button type="primary" loading={busy} disabled={!ready} onClick={() => { if (ready) onApply({ confirm_apply: apply, confirm_upsert: upsert, confirm_live: live, confirm_unknown_overlap: overlap }); }}>
      {text('发送一次明确的新发布', 'Send one explicit new publication')}
    </Button>
  </Space>;
}
