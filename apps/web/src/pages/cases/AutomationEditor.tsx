import { useState } from 'react';
import { Alert, Button, Checkbox, Collapse, Form, Input, Modal, Select, Space, Switch, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { callApi, useApiQuery } from '@/api/client';
import { automationsApi, type Automation, type AutomationPreview, type PlaybookDefinition } from '@/api/soarAutomations';
import { integrationsApi } from '@/api/integrations';
import type { Asset, AssetProfile } from '@/types/domain';

const targets: Record<string, [string, string, string][]> = {
  'block-domain': [['domain', '封禁域名（不含协议、路径）', 'Domain to block (no scheme or path)']],
  'revoke-credential': [['api_key_id', '待吊销的平台 API Key ID', 'Platform API key ID to revoke']],
  'isolate-host': [['reason', '隔离原因', 'Isolation reason']],
  'deactivate-external-user': [['reason', '停用原因', 'Deactivation reason']],
};
const initial: PlaybookDefinition = { key: 'case-review-only', name: 'Create a case for human triage',
  trigger: { min_severity: 'high' }, enabled: true, require_approval: false, timeout_secs: 300,
  steps: [{ name: 'Record case for analyst', params: { condition: 'true' } }] };

function responseMode(action: string, settingsJson: string, mock: boolean): string {
  if (mock) return 'Mock';
  if (action !== 'isolate-host') return 'Live';
  try { return JSON.parse(settingsJson || '{}').dry_run === false ? 'Live' : 'EDR dry-run'; }
  catch { return 'EDR dry-run'; }
}

export default function AutomationEditor({ item, onClose, onSaved }: {item?: Automation; onClose: () => void; onSaved: () => void}) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [book, setBook] = useState<PlaybookDefinition>(item?.playbook ?? initial);
  const [yaml, setYaml] = useState(JSON.stringify(item?.playbook ?? initial, null, 2));
  const [advanced, setAdvanced] = useState(Boolean(item && item.playbook.steps.length !== 1));
  const [enabled, setEnabled] = useState(item?.enabled ?? false);
  const [separate, setSeparate] = useState(item?.separateApprover ?? false);
  const [reason, setReason] = useState('');
  const [alertId, setAlertId] = useState('');
  const [preview, setPreview] = useState<AutomationPreview>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [assetSearch, setAssetSearch] = useState('');
  const templates = useApiQuery('soar-templates', automationsApi.templates);
  const action = book.steps[0]?.action ?? '';
  const fields = targets[action] ?? [];
  const external = action === 'isolate-host' || action === 'deactivate-external-user';
  const adapter = action === 'isolate-host' ? 'edr-isolation' : 'iam-scim';
  const assetId = String(book.steps[0]?.params?.asset_id ?? '');
  const assets = useApiQuery('automation-target-assets', () => callApi<{ items: Asset[] }>(
    '/api/v1/assets', () => { throw new Error('Assets unavailable'); },
    { noFallback: true, query: { keyword: assetSearch, page_size: 100 } }),
  { key: [assetSearch], enabled: external && !advanced });
  const targetAsset = useApiQuery('automation-target-asset', () => callApi<AssetProfile>(
    `/api/v1/assets/${encodeURIComponent(assetId)}`, () => { throw new Error('Asset unavailable'); }, { noFallback: true }),
  { key: [assetId], enabled: external && !advanced && Boolean(assetId) });
  const integration = useApiQuery('automation-target-integration', () => integrationsApi.configuration(adapter),
    { key: [adapter], enabled: external && !advanced });
  const asset = targetAsset.data?.data.asset;
  const binding = action === 'isolate-host' ? asset?.edrHostId?.trim() : asset?.scimUserId?.trim();
  const configuration = integration.data?.data;
  const mode = configuration && responseMode(action, configuration.settingsJson,
    configuration.mock || configuration.environmentMock);
  const effectiveBook = external && !advanced ? { ...book, require_approval: true, steps: [{ ...book.steps[0], params: {
    ...book.steps[0].params, asset_id: assetId, [action === 'isolate-host' ? 'host_id' : 'user_id']: binding ?? '',
    configuration_version: configuration?.version ?? 0,
  } }] } : book;
  const missingExternalTarget = enabled && !advanced && external && (!assetId || !binding || !configuration?.enabled ||
    !configuration.version || ['deprecated', 'retired'].includes(asset?.lifecycle ?? '') ||
    (action === 'deactivate-external-user' && asset?.kind !== 'credential') ||
    !String(book.steps[0]?.params?.reason ?? '').trim());
  const change = (next: PlaybookDefinition) => { setBook(next); setYaml(JSON.stringify(next, null, 2)); setPreview(undefined); };
  const definition = () => advanced ? { yaml } : { playbook: effectiveBook };
  const save = async () => {
    setBusy(true); setError('');
    try { await automationsApi.save(item?.id, { ...definition(), expected_version: item?.version ?? 0, enabled, separate_approver: separate, reason }); onSaved(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  };
  const evaluate = async () => {
    setBusy(true); setError(''); setPreview(undefined);
    try { setPreview((await automationsApi.preview({ ...definition(), alert_id: alertId.trim() })).data); }
    catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  };
  return <Modal open width={960} title={`${text('配置自动响应', 'Configure automatic response')} · v${item?.version ?? 0}`}
    confirmLoading={busy} onOk={() => void save()} onCancel={() => !busy && onClose()} maskClosable={!busy}
    okText={text('保存配置', 'Save configuration')} okButtonProps={{ 'aria-label': text('保存配置', 'Save configuration'), disabled: busy || !reason.trim() || (!advanced && (!book.name.trim() || missingExternalTarget)) }}>
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Alert type="info" showIcon message={text('默认停用。预览不会创建案件或执行动作；启用后只处理新建告警。', 'Disabled by default. Preview creates no case and performs no action. Enabling applies to new alerts.')}
        description={text('停用不会撤销已经提交的任务，请到对应案件审批或取消。变更冲突时保留当前输入，请复制后关闭并重新打开最新版本。', 'Disabling does not cancel submitted runs. Review or cancel them in their cases. If a revision conflicts, copy your edits, close and reopen the latest revision.')} />
      {!item && <Alert type="info" showIcon message={text('每租户最多 50 个自动响应配置，已停用的配置也占名额。', 'Each tenant supports at most 50 automation configurations. Disabled configurations still occupy a slot.')}
        description={text('达到上限时，保存会失败并保留草稿。复制需要保留的输入，返回列表，选择“编辑 / 启停”修改已有配置；停用不会释放名额。', 'At capacity, saving fails and keeps your draft. Copy the input you need, return to the list and choose “Edit / enable” on an existing configuration. Disabling does not free a slot.')} />}
      <Select aria-label={text('起始模板', 'Starting template')} placeholder={text('选择模板', 'Choose a template')} style={{ width: '100%' }}
        options={(templates.data?.data.items ?? []).map(row => ({ value: row.key, label: zh ? row.nameZh : row.nameEn }))}
        onChange={key => { const chosen = templates.data?.data.items.find(row => row.key === key); if (chosen) { const name = zh ? chosen.nameZh : chosen.nameEn;
          change({ ...chosen.playbook, name, steps: chosen.playbook.steps.map(step => ({ ...step, name })) }); setAdvanced(false); } }} />
      {templates.error && <Alert type="error" message={String(templates.error)} />}
      <Checkbox checked={advanced} onChange={event => {
        if (event.target.checked) { setYaml(JSON.stringify(book, null, 2)); setAdvanced(true); }
        else { try { const parsed = JSON.parse(yaml) as PlaybookDefinition; if (!parsed.trigger || !Array.isArray(parsed.steps) || parsed.steps.length !== 1) throw new Error(); setBook(parsed); setAdvanced(false); setError(''); }
          catch { setError(text('复杂 YAML 请继续使用高级模式；选择起始模板可重建表单。', 'Keep advanced mode for complex YAML. Choose a starting template to rebuild the form.')); } }
      }}>{text('高级 YAML / JSON 编辑', 'Advanced YAML / JSON editor')}</Checkbox>
      {advanced ? <Input.TextArea aria-label="Playbook YAML" rows={14} value={yaml} onChange={event => { setYaml(event.target.value); setPreview(undefined); }} /> :
        <Form layout="vertical">
          <Form.Item label={text('名称', 'Name')} required><Input aria-label={text('自动响应名称', 'Automation name')} value={book.name} onChange={event => change({ ...book, name: event.target.value })} /></Form.Item>
          <Form.Item label={text('最低告警等级', 'Minimum alert severity')}><Select value={book.trigger.min_severity} options={['info', 'low', 'medium', 'high', 'critical'].map(value => ({value, label:value}))}
            onChange={value => change({ ...book, trigger: { ...book.trigger, min_severity: value } })} /></Form.Item>
          <Form.Item label={text('规则键（空表示不限）', 'Rule keys (empty matches any)')}><Select mode="tags" tokenSeparators={[',']} value={book.trigger.rule_keys ?? []}
            onChange={value => change({ ...book, trigger: { ...book.trigger, rule_keys: value } })} /></Form.Item>
          {external && <>
            <Form.Item label={text('目标资产', 'Target asset')} required><Select showSearch filterOption={false} onSearch={setAssetSearch}
              loading={assets.isLoading} value={assetId || undefined} placeholder={text('搜索并选择已绑定资产', 'Search for a bound asset')}
              options={[...(assets.data?.data.items.filter(row => action !== 'deactivate-external-user' || row.kind === 'credential')
                .map(row => ({ value: row.id, label: `${row.name} · ${row.id}` })) ?? []),
              ...(asset && !assets.data?.data.items.some(row => row.id === asset.id)
                ? [{ value: asset.id, label: `${asset.name} · ${asset.id}` }] : [])]}
              onChange={value => change({ ...book, steps: [{ ...book.steps[0], params: { ...book.steps[0].params, asset_id: value } }] })} /></Form.Item>
            {assets.error && <Alert type="error" message={String(assets.error)} />}
            {targetAsset.error && <Alert type="error" message={String(targetAsset.error)} />}
            {integration.error && <Alert type="error" message={String(integration.error)} />}
            <Alert type={binding && configuration?.enabled && mode !== 'Live' ? 'info' : 'warning'} showIcon
              message={binding && configuration?.enabled
                ? text(`已绑定远端编号 ${binding} · ${adapter} 配置版本 ${configuration.version} · ${mode}`,
                  `Bound remote ID ${binding} · ${adapter} configuration v${configuration.version} · ${mode}`)
                : text('先绑定远端编号并启用集成配置', 'Bind the remote ID and enable the integration first')} />
          </>}
          {fields.length ? fields.map(([key, cn, en]) => <Form.Item key={key} label={zh ? cn : en} required>
            <Input aria-label={zh ? cn : en} value={String(book.steps[0]?.params?.[key] ?? '')}
              onChange={event => change({ ...book, steps: [{ ...book.steps[0], params: { ...book.steps[0].params, [key]: event.target.value } }] })} />
          </Form.Item>) : action === 'isolate-agent' ?
            <Alert type="info" message={text('隔离目标来自告警关联的唯一 Agent。若有多个 Agent，请在高级 YAML 中用 params.asset_id 明确指定关联目标。', 'Isolation uses the single Agent linked to the alert. For multiple Agents, specify a linked target in params.asset_id using advanced YAML.')} /> : null}
          {!action && <Alert type="info" message={text('只创建关联告警、发现和资产的案件，不执行处置或发送外部请求。', 'Creates a case linked to the alert, findings and assets, with no response action or external call.')} />}
          {external && <Alert type="warning" showIcon message={text('外部处置必须审批；只有新告警关联此资产时才可执行',
            'External response requires approval and an alert linked to this asset')}
            description={text('页面从资产与集成配置读取远端编号和版本；启用时服务端会再次核对，配置或绑定变化后需修改自动响应。',
              'The page reads the remote ID and version from the asset and integration. The server checks both at enablement; update this automation after changes.')} />}
          <Checkbox checked={external || book.require_approval === true} disabled={external}
            onChange={event => change({ ...book, require_approval: event.target.checked })}>{text('执行前人工审批', 'Require approval before execution')}</Checkbox>
        </Form>}
      <Checkbox checked={separate} onChange={event => setSeparate(event.target.checked)}>{text('企业双人复核：由发布者以外的管理员批准', 'Two-person review: require a different administrator')}</Checkbox>
      <Space><Switch checked={enabled} onChange={setEnabled} /><Typography.Text>{text('启用自动触发', 'Enable automatic triggering')}</Typography.Text></Space>
      <Input.TextArea aria-label={text('变更说明', 'Change reason')} placeholder={text('填写变更说明', 'Describe the change')} value={reason} maxLength={2000} onChange={event => setReason(event.target.value)} />
      <Collapse items={[{ key: 'preview', label: text('匹配预览（无副作用）', 'Trigger preview (no side effects)'), children: <Space direction="vertical" style={{ width: '100%' }}>
        <Input aria-label={text('预览告警 ID', 'Preview alert ID')} placeholder={text('从告警详情复制 ID', 'Copy an alert ID from its details')} value={alertId} onChange={event => { setAlertId(event.target.value); setPreview(undefined); }} />
        <Button loading={busy} disabled={!alertId.trim()} onClick={() => void evaluate()}>{text('检查匹配与目标', 'Check match and targets')}</Button>
        {preview && <><Alert type={preview.matches && preview.active ? 'success' : 'info'} message={preview.matches && preview.active ? text('匹配：请核对以下目标', 'Matched: review the targets below') : text('不匹配或告警不活跃', 'Not matched or alert inactive')} />
          <pre style={{ maxHeight: 200, overflow: 'auto', whiteSpace: 'pre-wrap' }}>{JSON.stringify(preview, null, 2)}</pre></>}
      </Space> }]} />
      {error && <Alert type="error" showIcon message={error} />}
    </Space>
  </Modal>;
}
