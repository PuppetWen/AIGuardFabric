import { useState } from 'react';
import { Alert, Button, Checkbox, InputNumber, Select, Space, Typography } from 'antd';
import type { ConfigurationChange, ConfigurationObservation, ConfigurationOperation, ConfigurationState, ContentSettings, ServicePatch } from '@/types/apigConfigurationPublication';
import { matching, unknownReady } from './eligibility';
import { useApigText } from './text';

export default function ConfigurationCandidate({ data, baseline, operation, rollbackId, busy, held, canWrite, onPublishMode, onPrepare, onChange, onRead }: {
  data: ConfigurationState; baseline: ConfigurationObservation | null; operation: ConfigurationOperation | null; rollbackId: string | null;
  busy: boolean; held: boolean; canWrite: boolean; onPublishMode: () => void; onPrepare: (change: ConfigurationChange, acknowledge: boolean) => void;
  onChange: () => void; onRead: (id: string) => void;
}) {
  const text = useApigText(), [settings, setSettings] = useState<ContentSettings | null>(baseline?.view.settings ?? null);
  const [services, setServices] = useState<ServicePatch[]>((baseline?.view.services ?? []).map(row => ({ ...row, expectedModelName: row.modelName })));
  const [acknowledge, setAcknowledge] = useState(false), unresolved = operation?.requestId === data.unresolvedOperationId ? operation
    : data.operations.find(row => row.requestId === data.unresolvedOperationId) ?? null;
  const unknownAllowed = !data.unresolvedOperationId || (!!baseline && acknowledge && unknownReady(data, baseline, unresolved));
  const disabled = busy || held || !canWrite, canPrepare = !disabled && data.canPrepare && matching(data, baseline) && unknownAllowed;
  const history = data.history.find(row => row.publicationId === rollbackId);
  const totalWeight = services.reduce((sum, row) => sum + row.weight, 0);
  const validServices = services.length > 0 && services.length <= data.limits.maxServices && totalWeight === 100
    && services.every(row => !!row.modelName && row.modelName === row.modelName.trim() && Number.isInteger(row.weight) && row.weight > 0 && row.weight <= 100);
  const prepare = () => {
    if (!canPrepare) return;
    if (rollbackId) { if (history?.rollbackAvailable) onPrepare({ action: 'rollback', publication_id: rollbackId }, acknowledge); }
    else if (baseline?.target.binding.kind === 'content' && settings && Number.isInteger(settings.denyCode) && settings.denyCode >= 100 && settings.denyCode <= 599)
      onPrepare({ action: 'content', settings: { ...settings } }, acknowledge);
    else if (baseline?.target.binding.kind === 'models' && validServices) onPrepare({ action: 'models', services: services.map(row => ({ ...row })) }, acknowledge);
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('公开配置草稿（未发送云写）', 'Public configuration draft (no cloud write sent)')}</Typography.Title>
    {!baseline && <Alert type="info" message={text('先明确观察并采用基线；不会自动使用示例或最新配置。', 'Observe and adopt a baseline explicitly; examples or the latest configuration are never selected automatically.')} />}
    {baseline && !matching(data, baseline) && <Alert type="warning" message={text('草稿保留，但当前来源或最新观察已变化。先比较，再明确采用；不会自动换版本。',
      'The draft remains, but the source or latest observation changed. Compare and adopt explicitly; revisions never change automatically.')} />}
    {rollbackId ? <>
      <Typography.Text>{text('已明确选择可信历史', 'Explicitly selected trusted history')}: {rollbackId}</Typography.Text>
      {(!history?.rollbackAvailable) && <Alert type="warning" message={history?.reason ?? text('此历史当前不能回滚', 'This history is not currently available for rollback')} />}
      <Button disabled={disabled} onClick={onPublishMode}>{text('明确返回编辑新配置', 'Explicitly return to editing new configuration')}</Button>
    </> : baseline?.target.binding.kind === 'content' && settings ? <>
      {(['enabled', 'checkRequest', 'checkResponse'] as const).map(key => <Checkbox key={key} checked={settings[key]} disabled={disabled}
        onChange={event => { setSettings(old => old && { ...old, [key]: event.target.checked }); onChange(); }}>{key}</Checkbox>)}
      <InputNumber aria-label={text('内容拒绝响应码', 'Content deny response code')} value={settings.denyCode} min={100} max={599} precision={0} disabled={disabled}
        onChange={value => { setSettings(old => old && { ...old, denyCode: value ?? 0 }); onChange(); }} />
      <Alert type="warning" message={text('checkResponse 可能把流式响应变成非流式；私密规则保持原样。', 'checkResponse may make streaming responses non-streaming; private rules are preserved.')} />
    </> : baseline?.target.binding.kind === 'models' ? <>
      <Typography.Text>{text('仅编辑观察到的已有服务；服务身份/版本保持，权重总和须为 100。', 'Edit only observed existing services; service identity/revision is retained and weights must total 100.')}</Typography.Text>
      {services.map((row, index) => <Space key={`${row.serviceId}:${row.version}:${row.expectedModelName}`} wrap>
        <Typography.Text code>{row.serviceId} / {row.version ?? text('无版本字段', 'No revision field')}</Typography.Text>
        <Select style={{ minWidth: 180 }} aria-label={`${text('模型名', 'Model name')} ${index + 1}`} value={row.modelName} disabled={disabled}
          options={[...new Set((baseline.view.services ?? []).filter(item => item.serviceId === row.serviceId && item.version === row.version).map(item => item.modelName))].map(value => ({ value, label: value }))}
          onChange={value => { setServices(old => old.map((item, i) => i === index ? { ...item, modelName: value } : item)); onChange(); }} />
        <InputNumber aria-label={`${text('服务权重', 'Service weight')} ${index + 1}`} value={row.weight} min={1} max={100} precision={0} disabled={disabled}
          onChange={value => { setServices(old => old.map((item, i) => i === index ? { ...item, weight: value ?? 0 } : item)); onChange(); }} />
      </Space>)}
      <Typography.Text>{text('权重总和', 'Weight total')}: {totalWeight}</Typography.Text>
    </> : null}
    {data.unresolvedOperationId && <>
      <Alert type="warning" message={text('旧 Unknown 不能安全重试；先恢复其本地事实，租约后重新观察，再明确确认独立新意图可能与旧请求重叠。',
        'The old Unknown cannot be safely retried. Recover its local fact, observe after its lease, then explicitly acknowledge possible overlap for a separate new intent.')} />
      <Button onClick={() => onRead(data.unresolvedOperationId!)}>{text('读取阻挡的新意图原 UUID', 'Read the original UUID blocking a new intent')}</Button>
      <Checkbox checked={acknowledge} disabled={disabled || !baseline || !unknownReady(data, baseline, unresolved)} onChange={e => setAcknowledge(e.target.checked)}>
        {text('明确承认旧 Unknown，准备独立新意图', 'Explicitly acknowledge the old Unknown for a separate new intent')}</Checkbox>
    </>}
    <Button disabled={!canPrepare || (rollbackId ? !history?.rollbackAvailable : baseline?.target.binding.kind === 'models' ? !validServices : !settings)} onClick={prepare}>
      {text('准备 APIG 配置预览', 'Prepare APIG configuration preview')}</Button>
  </Space>;
}
