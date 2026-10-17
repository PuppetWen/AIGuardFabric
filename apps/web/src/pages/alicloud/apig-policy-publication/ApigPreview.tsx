import { useState } from 'react';
import { Alert, Button, Checkbox, Descriptions, Space, Typography } from 'antd';
import type { ApigPreview as Preview, ApigPublicationState, ApplyConfirmations } from '@/types/apigPolicyPublication';
import { applicable } from './eligibility';
import { revisions, useApigText } from './text';

export default function ApigPreview({ preview, data, attempted, canWrite, busy, onApply }: {
  preview: Preview; data: ApigPublicationState; attempted: string | null; canWrite: boolean; busy: boolean;
  onApply: (confirm: ApplyConfirmations) => void;
}) {
  const text = useApigText();
  const [confirm, setConfirm] = useState<ApplyConfirmations>({ confirm_apply: false, confirm_scope_difference: false,
    confirm_shared_policy_impact: false, confirm_no_cloud_cas: false, confirm_live: false, confirm_unknown_overlap: false });
  const required = confirm.confirm_apply && confirm.confirm_scope_difference && confirm.confirm_shared_policy_impact && confirm.confirm_no_cloud_cas
    && (preview.target.transportMode !== 'live' || confirm.confirm_live) && (!preview.unknownOverlapWarning || confirm.confirm_unknown_overlap);
  const rows: [keyof ApplyConfirmations, string, string][] = [
    ['confirm_apply', '确认上述目标、原阈值、目标阈值与签名来源版本', 'Confirm the target, previous and desired thresholds and signed source revisions above'],
    ['confirm_scope_difference', '确认平台 Tenant minute 额度与云 API-global 周期不等价', 'Confirm platform Tenant minute quotas differ from the cloud API-global counting period'],
    ['confirm_shared_policy_impact', '确认独立策略可能被其它 API 引用，影响范围未知', 'Confirm the independent policy may be referenced by other APIs and shared impact is unknown'],
    ['confirm_no_cloud_cas', '确认云无 CAS，写前比较不能排除外部并发修改', 'Confirm there is no cloud CAS; the pre-write comparison cannot exclude external concurrent edits'],
    ...(preview.target.transportMode === 'live' ? [['confirm_live', '确认向上述 Live 目标发送一次云 PUT', 'Confirm one cloud PUT to the Live target above'] as [keyof ApplyConfirmations, string, string]] : []),
    ...(preview.unknownOverlapWarning ? [['confirm_unknown_overlap', '确认这是独立新意图，旧 Unknown 仍可能到达且不能保证已停止', 'Confirm this is a separate new intent; the old Unknown may still arrive and is not guaranteed to have stopped'] as [keyof ApplyConfirmations, string, string]] : []),
  ];
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('可信 APIG 预览（未发送云写）', 'Trusted APIG preview (no cloud write sent)')}</Typography.Title>
    <Descriptions bordered size="small" column={2} items={[
      { key: 'slot', label: text('仅此已有 slot', 'Only this existing slot'), children: preview.managedLimit },
      { key: 'limit', label: text('原阈值 → 目标阈值', 'Previous → desired threshold'), children: `${preview.previousLimit} → ${preview.desiredLimit}` },
      { key: 'target', label: 'Policy / API', children: `${preview.target.binding.policyId} / ${preview.target.binding.httpApiId}` },
      { key: 'source', label: text('原来源版本', 'Source revisions'), children: revisions(preview.sourcePolicyVersions) },
      { key: 'hash', label: text('原 hash → 目标 hash', 'Baseline → desired hash'), children: `${preview.baselineConfigHash} → ${preview.desiredHash}` },
      { key: 'expiry', label: text('状态版本 / 到期', 'State revision / expiry'), children: `${preview.stateVersion} / ${preview.expiresAt}` },
      { key: 'rollback', label: text('回滚来源', 'Rollback source'), children: preview.sourcePublicationId ?? '—' },
    ]} />
    <Alert type="warning" message={text('共享影响、消费者加载均未知；没有云 CAS。', 'Shared impact and consumer loading remain unknown; there is no cloud CAS.')}
      description={text('只修改一个已有 Global minute slot，保留其它配置。回滚把可信历史的 previousThreshold 放到新观察基线上，使用新请求编号；不是还原整个旧云对象。',
        'Only one existing Global minute slot changes; other configuration is retained. Rollback places the trusted historical previous threshold onto a fresh baseline with a new request ID; it does not restore the entire old cloud object.')} />
    {preview.reason && <Alert type="warning" message={preview.reason} />}
    {rows.map(([key, cn, en]) => <Checkbox key={key} checked={confirm[key]} disabled={busy || !canWrite || attempted === preview.id}
      onChange={event => setConfirm(old => ({ ...old, [key]: event.target.checked }))}>{text(cn, en)}</Checkbox>)}
    <Button type="primary" disabled={busy || !canWrite || !required || !applicable(data, preview, attempted)} onClick={() => onApply({ ...confirm })}>
      {text('发送一次明确的新 APIG 发布', 'Send one explicit new APIG publication')}</Button>
    {attempted === preview.id && <Alert type="info" message={text('此预览已经尝试发送，禁止再次发送。保留原 UUID 并只读取回执或本地恢复。',
      'This preview was already submitted and cannot be resent. Retain the original UUID and only read its receipt or recover locally.')} />}
  </Space>;
}
