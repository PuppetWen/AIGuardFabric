import { useEffect, useState } from 'react';
import { Alert, Button, Checkbox, Input, Space, Typography } from 'antd';
import type { ApplyConfirmations, ConfigurationPreview as Preview, ConfigurationState } from '@/types/apigConfigurationPublication';
import { useApigText } from './text';

export default function ConfigurationPreview({ preview, data, held, busy, canWrite, onApply }: {
  preview: Preview; data: ConfigurationState; held: boolean; busy: boolean; canWrite: boolean; onApply: (confirm: ApplyConfirmations) => void;
}) {
  const text = useApigText(), [confirm, setConfirm] = useState<ApplyConfirmations>({ confirm_apply: false, confirm_preserved_private_configuration: false,
    confirm_streaming_or_shared_impact: false, confirm_no_cloud_cas: false, confirm_live: false, confirm_unknown_overlap: false });
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const required = confirm.confirm_apply && confirm.confirm_preserved_private_configuration && confirm.confirm_streaming_or_shared_impact && confirm.confirm_no_cloud_cas
    && (preview.target.transportMode !== 'live' || confirm.confirm_live) && (!preview.unknownOverlapWarning || confirm.confirm_unknown_overlap);
  const valid = preview.previewUsable && preview.allowedActions.includes('apply') && !preview.consumedBy && data.canApply
    && preview.stateVersion === data.stateVersion && preview.target.targetScopeId === data.binding?.targetScopeId
    && preview.target.configurationVersion === data.binding?.configurationVersion && Date.parse(preview.expiresAt) > now;
  const rows: [keyof ApplyConfirmations, string, string][] = [
    ['confirm_apply', '确认上述目标和公开配置差异', 'Confirm the target and public configuration differences above'],
    ['confirm_preserved_private_configuration', '确认只改公开字段，保留其它环境、凭据和私密规则', 'Confirm public fields only, retaining other environments, credentials and private rules'],
    ['confirm_streaming_or_shared_impact', '确认流式响应与其它资源共享影响未知', 'Confirm streaming-response and shared-resource impact remain unknown'],
    ['confirm_no_cloud_cas', '确认云无 CAS，写前比较仍不能排除外部并发', 'Confirm there is no cloud CAS; pre-write comparison cannot exclude external concurrency'],
    ...(preview.target.transportMode === 'live' ? [['confirm_live', '确认向此 Live 目标发送一次配置 PUT', 'Confirm one configuration PUT to this Live target'] as [keyof ApplyConfirmations, string, string]] : []),
    ...(preview.unknownOverlapWarning ? [['confirm_unknown_overlap', '确认独立新意图；旧 Unknown 仍可能到达', 'Confirm a separate new intent; the old Unknown may still arrive'] as [keyof ApplyConfirmations, string, string]] : []),
  ];
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('可信 APIG 配置预览', 'Trusted APIG configuration preview')}</Typography.Title>
    <Typography.Text>{text('状态版本 / 到期 / 回滚来源', 'State revision / expiry / rollback source')}: {preview.stateVersion} / {preview.expiresAt} / {preview.sourcePublicationId ?? '—'}</Typography.Text>
    <Input.TextArea readOnly rows={8} aria-label={text('APIG 公开配置差异', 'APIG public configuration differences')} value={JSON.stringify(preview.diff, null, 2)} />
    <Alert type="warning" message={text('这只是配置写入，不是云部署或消费者加载证明。Model API 保存后按云控制台提示 Publish/Apply，并独立验证业务。',
      'This is a configuration write, not proof of cloud deployment or consumer loading. After saving Model API configuration, follow cloud-console Publish/Apply prompts and verify the actual workload separately.')} />
    {preview.reason && <Alert type="warning" message={preview.reason} />}
    {rows.map(([key, cn, en]) => <Checkbox key={key} checked={confirm[key]} disabled={busy || held || !canWrite}
      onChange={e => setConfirm(old => ({ ...old, [key]: e.target.checked }))}>{text(cn, en)}</Checkbox>)}
    <Button type="primary" disabled={busy || held || !canWrite || !required || !valid} onClick={() => { if (Date.parse(preview.expiresAt) > Date.now()) onApply({ ...confirm }); }}>
      {text('发送一次明确的新 APIG 配置写入', 'Send one explicit new APIG configuration write')}</Button>
    {held && <Alert type="info" message={text('已保留原意图，禁止重复发送；读取其 UUID 或明确恢复本地。', 'The original intent is retained and cannot be resent; read its UUID or recover locally explicitly.')} />}
  </Space>;
}
