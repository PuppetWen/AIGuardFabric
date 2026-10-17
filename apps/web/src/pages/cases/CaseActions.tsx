import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Form, Input, Modal, Popconfirm, Select, Space, Switch, Table, Typography } from 'antd';
import { api, callApi, useApiQuery } from '@/api/client';
import { casesApi, type PlaybookResult } from '@/api/cases';
import { gatewayApi } from '@/api/gateway';
import type { AssetProfile, Case } from '@/types/domain';
import { caseWorkflowsApi } from '@/api/caseWorkflows';
import { integrationsApi, type IntegrationConfig } from '@/api/integrations';
import CaseWorkflows from './CaseWorkflows';

const actions = [
  ['isolate-agent', '隔离 Agent 出口', 'Isolate Agent egress', 'asset_id'],
  ['isolate-host', '通过 EDR 隔离主机', 'Isolate host through EDR', 'asset_id'],
  ['deactivate-external-user', '通过 SCIM 停用外部身份', 'Deactivate external identity through SCIM', 'asset_id'],
  ['revoke-credential', '吊销平台 API Key', 'Revoke platform API key', 'api_key_id'],
  ['block-domain', '封禁域名', 'Block domain', 'domain'],
  ['block-ip', '封禁 IP', 'Block IP', 'ip'],
  ['kill-session', '终止代理会话', 'Terminate proxy session', 'session_id'],
  ['force-local-model', '强制本地模型', 'Force local model', 'asset_id'],
  ['disable-mcp-server', '禁用 MCP 工具', 'Disable MCP tools', 'asset_id'],
  ['revoke-skill', '撤销 Skill 工具访问', 'Revoke Skill tool access', 'asset_id'],
  ['notify-owner', '发送处置通知', 'Send case notification', 'channel'],
] as const;

function edrMode(config: IntegrationConfig): string {
  if (config.mock || config.environmentMock) return 'Mock';
  try {
    return JSON.parse(config.settingsJson || '{}').dry_run === false ? 'Live' : 'EDR dry-run';
  } catch {
    return 'EDR dry-run';
  }
}

export default function CaseActions({ item, onChange }: {item: Case; onChange: () => void}) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const label = (cn: string, en: string) => zh ? cn : en;
  const [open, setOpen] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [yaml, setYaml] = useState('');
  const [action, setAction] = useState<string>('isolate-agent');
  const [dryRun, setDryRun] = useState(true);
  const [separateApprover, setSeparateApprover] = useState(false);
  const [submitted, setSubmitted] = useState<string>();
  const [refreshToken, setRefreshToken] = useState(0);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PlaybookResult>();
  const [error, setError] = useState('');
  const [form] = Form.useForm();
  const selectedAssetId = Form.useWatch('target', form) as string | undefined;
  const controls = useApiQuery('case-controls', () => casesApi.controls(item.id), { key: [item.id], refetchInterval: 5000 });
  const keys = useApiQuery('case-action-keys', api.apiKeys, { enabled: open && action === 'revoke-credential' && !advanced });
  const models = useApiQuery('case-action-models', gatewayApi.list, { enabled: open && action === 'force-local-model' && !advanced });
  const edr = useApiQuery('case-action-edr', () => integrationsApi.configuration('edr-isolation'),
    { enabled: open && action === 'isolate-host' && !advanced });
  const iam = useApiQuery('case-action-iam', () => integrationsApi.configuration('iam-scim'),
    { enabled: open && action === 'deactivate-external-user' && !advanced });
  const externalAction = action === 'isolate-host' || action === 'deactivate-external-user';
  const targetAsset = useApiQuery('case-action-external-asset',
    () => callApi<AssetProfile>(`/api/v1/assets/${selectedAssetId}`, () => { throw new Error('Asset unavailable'); }, { noFallback: true }),
    { key: [selectedAssetId], enabled: open && externalAction && !advanced && Boolean(selectedAssetId) });
  const boundHostId = targetAsset.data?.data.asset.edrHostId?.trim() ?? '';
  const boundUserId = targetAsset.data?.data.asset.scimUserId?.trim() ?? '';
  const field = actions.find((row) => row[0] === action)?.[3] ?? 'asset_id';
  const targetLabels: Record<string, string> = {
    asset_id: label('关联资产', 'Linked asset'), api_key_id: label('平台 API Key', 'Platform API key'),
    domain: label('域名（不含协议和路径）', 'Domain (without scheme or path)'), ip: label('IP 地址', 'IP address'),
    session_id: label('代理会话 ID', 'Proxy session ID'), channel: label('已配置的通知渠道', 'Configured notification channel'),
  };
  const options = (item.assetIds ?? []).map((id, index) => ({ value: id, label: item.assetNames[index] || id }));
  const resetResult = () => { setResult(undefined); setSubmitted(undefined); setError(''); };
  const refresh = () => { void controls.refetch(); onChange(); };
  const execute = async () => {
    setBusy(true); setError('');
    try {
      const values = await form.validateFields();
      if (!advanced && action === 'isolate-host' && !boundHostId) {
        throw new Error(label('请先在所选资产详情绑定 EDR 主机编号', 'Bind an EDR host ID in the selected asset details first'));
      }
      if (!advanced && action === 'isolate-host' && !dryRun && (!edr.data?.data.enabled || !edr.data.data.version)) {
        throw new Error(label('先在集成配置中启用 EDR 隔离并刷新配置', 'Enable EDR isolation in Integrations and refresh its configuration'));
      }
      if (!advanced && action === 'deactivate-external-user' &&
          (targetAsset.data?.data.asset.kind !== 'credential' || !boundUserId)) {
        throw new Error(label('请选择已绑定 SCIM 用户编号的凭据资产', 'Select a credential asset bound to a SCIM user ID'));
      }
      if (!advanced && action === 'deactivate-external-user' && !dryRun && (!iam.data?.data.enabled || !iam.data.data.version)) {
        throw new Error(label('先在集成中心启用 SCIM 身份平台并刷新配置', 'Enable the SCIM identity integration first'));
      }
      const body = advanced ? { yaml } : { playbook: {
        key: 'console-case-action', name: label('控制台案件处置', 'Console case action'), trigger: {}, timeout_secs: 120,
        require_approval: true, steps: [{ name: actions.find((row) => row[0] === action)?.[zh ? 1 : 2] ?? action,
          action, params: { [field]: values.target, reason: values.reason, endpoint_id: values.endpoint,
            host_id: boundHostId, user_id: boundUserId,
            configuration_version: action === 'isolate-host' ? edr.data?.data.version : iam.data?.data.version }, timeout_secs: 60 }],
      } };
      if (dryRun) {
        const response = await casesApi.execute(item.id, { ...body, dry_run: true, approve: false });
        setResult(response.data);
      } else {
        const response = await caseWorkflowsApi.submit(item.id, { ...body, separate_approver: separateApprover });
        setSubmitted(response.data.run.id); setRefreshToken(value => value + 1);
      }
      refresh();
    } catch (cause) { if (cause instanceof Error) setError(cause.message); }
    finally { setBusy(false); }
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Button type="primary" disabled={!controls.data?.data.canWrite} onClick={() => { setOpen(true); resetResult(); }}>
      {label('执行处置 / YAML 剧本', 'Run action / YAML playbook')}
    </Button>
    {controls.error && <Alert type="error" message={String(controls.error)} />}
    {!!controls.data?.data.items.length && <Table size="small" rowKey="id" pagination={{ pageSize: 5 }}
      dataSource={controls.data.data.items} columns={[
        { title: label('动作 / 目标', 'Action / target'), render: (_, row) => <div>{actions.find((a) => a[0] === row.action)?.[zh ? 1 : 2] ?? row.action}<br />{row.target}</div> },
        { title: label('原因', 'Reason'), dataIndex: 'reason' },
        { title: label('状态', 'Status'), render: (_, row) => row.active ? label('生效中', 'Active') : label('已解除', 'Released') },
        { title: label('操作', 'Action'), render: (_, row) => row.active && <Popconfirm title={label('确认解除此处置？', 'Release this control?')}
          onConfirm={async () => { try { await casesApi.release(item.id, row.id); refresh(); } catch (cause) { setError(String(cause)); } }}>
          <Button size="small" disabled={busy || !controls.data?.data.canRelease}>{label('解除', 'Release')}</Button></Popconfirm> },
      ]} />}
    {error && !open && <Alert type="error" message={error} />}
    <CaseWorkflows caseId={item.id} refreshToken={refreshToken} onChange={refresh} />
    <Modal open={open} width={760} title={label('案件处置', 'Case containment')} onCancel={() => !busy && setOpen(false)}
      okText={dryRun ? label('演练', 'Dry run') : label('提交执行任务', 'Submit run')} onOk={() => void execute()}
      confirmLoading={busy} okButtonProps={{ disabled: Boolean(result || submitted) }} maskClosable={!busy} cancelButtonProps={{ disabled: busy }}>
      <Space direction="vertical" style={{ width: '100%' }} size="middle">
        <Alert type={externalAction && !advanced ? 'warning' : 'info'} showIcon
          message={externalAction && !advanced
            ? label('外部处置会调用已配置的平台', 'External response calls a configured platform')
            : label('其他动作影响平台代理流量和平台凭据', 'Other actions affect managed traffic and credentials')}
          description={externalAction && !advanced
            ? label('先在集成页配置对应平台，并在资产详情绑定远端编号。Mock 不连接外部平台；真实调用必须从此处提交持久化任务并审批。EDR 另受 dry_run 设置控制。',
              'Configure the platform and bind the exact remote ID in asset details. Mock makes no external call. Live calls require a durable approved case run. EDR also obeys dry_run.')
            : label('Agent 隔离会拒绝新的 MCP/模型请求及返回检查；MCP/Skill 按端点或工具名拦截。API Key 吊销不可撤销。',
              'Agent isolation rejects new MCP/model requests and response checks. MCP/Skill controls target endpoints or tool names. API key revocation cannot be undone.')} />
        <Checkbox checked={advanced} onChange={(e) => { setAdvanced(e.target.checked); resetResult(); }}>{label('使用 YAML 剧本', 'Use YAML playbook')}</Checkbox>
        <Form form={form} layout="vertical" onValuesChange={resetResult} preserve={false}>
          {advanced ? <Form.Item label="YAML" required><Input.TextArea rows={12} value={yaml} onChange={(e) => { setYaml(e.target.value); resetResult(); }}
            placeholder={'key: isolate-agent\nname: Isolate Agent\ntrigger: {}\nsteps:\n  - name: Isolate\n    action: isolate-agent\n    params:\n      asset_id: <asset UUID>'} /></Form.Item> : <>
            <Form.Item label={label('动作', 'Action')} htmlFor="case-containment-action"><Select id="case-containment-action" value={action} options={actions.map((row) => ({ value: row[0], label: row[zh ? 1 : 2] }))}
              onChange={(value) => { setAction(value); form.resetFields(); resetResult(); }} /></Form.Item>
            <Form.Item name="target" label={targetLabels[field]} rules={[{ required: true, whitespace: true }]}>
              {field === 'asset_id' ? <Select showSearch optionFilterProp="label" options={options} placeholder={label('选择案件关联资产', 'Select a linked case asset')} /> :
                field === 'api_key_id' ? <Select showSearch optionFilterProp="label" loading={keys.isLoading} options={keys.data?.data.filter((key) => !key.revoked).map((key) => ({ value: key.id, label: key.name + ' · ' + key.id }))} /> :
                field === 'channel' ? <Select options={['in-app', 'email', 'dingtalk', 'feishu', 'wecom', 'webhook', 'pagerduty', 'sms'].map((value) => ({ value, label: value }))} /> : <Input />}
            </Form.Item>
            {keys.error && action === 'revoke-credential' && <Alert type="error" message={String(keys.error)} />}
            {action === 'isolate-host' && <>
              {selectedAssetId && <Alert type={boundHostId ? 'info' : 'warning'} showIcon
                message={boundHostId
                  ? label(`所选资产绑定的 EDR 主机：${boundHostId}`, `Selected asset's EDR host: ${boundHostId}`)
                  : label('所选资产尚未绑定 EDR 主机，请到资产详情设置',
                    'This asset has no EDR host binding. Set one in asset details.')} />}
              {targetAsset.error && <Alert type="error" message={String(targetAsset.error)} />}
              <Alert type={edr.data?.data.enabled ? 'info' : 'warning'} showIcon
                message={edr.data?.data.enabled
                  ? label(`EDR 配置版本 ${edr.data.data.version} · ${edrMode(edr.data.data)}`,
                    `EDR configuration v${edr.data.data.version} · ${edrMode(edr.data.data)}`)
                  : label('请先在集成配置中启用 EDR 隔离', 'Enable EDR isolation under Integrations first')} />
              {edr.error && <Alert type="error" message={String(edr.error)} />}
            </>}
            {action === 'deactivate-external-user' && <>
              {selectedAssetId && <Alert type={boundUserId ? 'info' : 'warning'} showIcon
                message={boundUserId
                  ? label(`所选资产绑定的 SCIM 用户：${boundUserId}`, `Selected asset's SCIM user: ${boundUserId}`)
                  : label('所选凭据资产尚未绑定 SCIM 用户，请到资产详情设置',
                    'Bind a SCIM user in the selected credential asset details first')} />}
              {targetAsset.error && <Alert type="error" message={String(targetAsset.error)} />}
              <Alert type={iam.data?.data.enabled ? 'info' : 'warning'} showIcon
                message={iam.data?.data.enabled
                  ? label(`SCIM 配置版本 ${iam.data.data.version} · ${iam.data.data.mock || iam.data.data.environmentMock ? 'Mock' : 'Live'}`,
                    `SCIM configuration v${iam.data.data.version} · ${iam.data.data.mock || iam.data.data.environmentMock ? 'Mock' : 'Live'}`)
                  : label('请先在集成配置中启用 SCIM 身份平台', 'Enable SCIM identity under Integrations first')} />
              {iam.error && <Alert type="error" message={String(iam.error)} />}
            </>}
            {action === 'force-local-model' && <Form.Item name="endpoint" label={label('本地模型端点', 'Local model endpoint')} rules={[{ required: true }]}>
              <Select showSearch optionFilterProp="label" loading={models.isLoading} options={models.data?.data.items.filter((model) => model.localDeployment && model.enabled)
                .map((model) => ({ value: model.id, label: model.name + ' · ' + model.model }))} />
            </Form.Item>}
            {models.error && action === 'force-local-model' && <Alert type="error" message={String(models.error)} />}
            <Form.Item name="reason" label={label('处置原因', 'Reason')} rules={[{ required: true, whitespace: true, max: 1024 }]}><Input.TextArea rows={2} /></Form.Item>
          </>}
        </Form>
        <Space><Switch checked={dryRun} onChange={(value) => { setDryRun(value); resetResult(); }} />{label('演练（不产生副作用）', 'Dry run (no side effects)')}</Space>
        {!dryRun && <>
          <Alert type="info" message={label('提交后在“审批与执行记录”中查看进度并审批；关闭网页不会取消任务。', 'After submission, review progress and approvals under Approvals and runs. Closing the page does not cancel the run.')} />
          <Checkbox checked={separateApprover} onChange={event => { setSeparateApprover(event.target.checked); resetResult(); }}>{label('要求另一位管理员审批（企业双人复核）', 'Require a different administrator (two-person review)')}</Checkbox>
        </>}
        {error && <Alert type="error" message={error} />}
        {submitted && <Alert type="info" message={label('任务已保存，请关闭窗口查看审批与执行记录', 'Run saved. Close this window to review approvals and progress')}
          description={<Typography.Text copyable>{submitted}</Typography.Text>} />}
        {result && <Alert type={result.hasFailure || result.outcome !== 'completed' ? 'error' : result.dryRun ? 'info' : 'success'}
          message={(result.dryRun ? label('演练结果：', 'Dry run: ') : label('实际执行：', 'Execution: ')) + result.outcome}
          description={<>{result.reason}<Typography.Paragraph copyable>{result.runId}</Typography.Paragraph>{result.steps.map((step, index) => <div key={index}>{step.name}: {step.error || step.note}</div>)}</>} />}
      </Space>
    </Modal>
  </Space>;
}
