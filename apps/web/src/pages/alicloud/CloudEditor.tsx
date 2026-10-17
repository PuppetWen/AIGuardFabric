import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Drawer, Form, Input, InputNumber, Select, Space, Spin, Switch, Tabs, Typography } from 'antd';
import { cloudApi, type CloudConfig } from '@/api/cloud';
import { useAuthStore } from '@/stores/authStore';
import { useSessionAccess } from '@/api/sessionAccess';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import CloudOperations from './CloudOperations';
import { CloudGuide } from './CloudGuide';
import { CloudInventory } from './CloudInventory';
import MseInventoryPanel from './mse/MseInventoryPanel';
import MseInventoryGuide from './mse/MseInventoryGuide';
import MseNamespaceFields from './mse/MseNamespaceFields';
import PrivateLinkInventoryPanel from './privatelink/PrivateLinkInventoryPanel';
import PrivateLinkInventoryGuide from './privatelink/PrivateLinkInventoryGuide';
import PrivateLinkEndpointFields from './privatelink/PrivateLinkEndpointFields';
import { configurationSettings, initialNamespace, type MseNamespaceSelection } from './mse/configurationSettings';
import { publicationAuthorizationSettings, validOptionalEngineOrigin } from './mse-config-publication/configurationAuthorization';
import { apigAuthorizationSettings } from './apig-policy-publication/configurationAuthorization';

const secretLabels = { access_key_id: 'AccessKey ID', access_key_secret: 'AccessKey Secret', security_token: 'Security Token' };
export default function CloudEditor({ name, onClose, onSaved }: { name: string; onClose: () => void; onSaved: () => void }) {
  const tenant = useAuthStore(state => state.tenant);
  const generation = useAuthStore(state => state.sessionGeneration);
  return <ScopedCloudEditor key={`${name}:${tenant?.id}:${tenant?.slug}:${generation}`} name={name} onClose={onClose} onSaved={onSaved} />;
}
function ScopedCloudEditor({ name, onClose, onSaved }: { name: string; onClose: () => void; onSaved: () => void }) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const access = useSessionAccess();
  const scope = useOperationScope();
  const canConfigure = access.has('alicloud:write');
  const [snapshot, setSnapshot] = useState<CloudConfig>();
  const [error, setError] = useState('');
  useEffect(() => {
    if (!canConfigure) return;
    const controller = new AbortController();
    void cloudApi.configuration(name, controller.signal).then(response => { if (!controller.signal.aborted && scope.current()) setSnapshot(response.data); })
      .catch(cause => { if (!controller.signal.aborted && scope.current()) setError(String(cause)); });
    return () => { controller.abort(); };
  }, [name, canConfigure, scope]);
  return <Drawer open width={850} title={snapshot?.displayName ?? name} onClose={onClose} destroyOnClose>
    {access.isLoading ? <Spin /> : !canConfigure ? name === 'alicloud-mse' ? <MseInventoryPanel />
      : name === 'alicloud-privatelink' ? <PrivateLinkInventoryPanel />
      : <Alert type="info" message={zh ? '查看和编辑连接配置需要 alicloud:write。' : 'Viewing and editing connection configuration requires alicloud:write.'} />
      : error ? <Alert type="error" message={error} /> : !snapshot ? <Spin /> : <Tabs items={[
      { key: 'config', label: zh ? '连接配置' : 'Connection', children: <Configuration key={snapshot.version} snapshot={snapshot} onSaved={value => { if (scope.current()) { setSnapshot(value); onSaved(); } }} /> },
      { key: 'operations', label: zh ? '操作与回执' : 'Operations', children: <CloudOperations key={snapshot.version} snapshot={snapshot} /> },
      ...(snapshot.name === 'alicloud-agentteams' ? [{ key: 'inventory', label: zh ? '台账同步' : 'Inventory sync', children: <CloudInventory key={snapshot.version} snapshot={snapshot} /> }] : []),
      ...(snapshot.name === 'alicloud-mse' ? [{ key: 'inventory', label: zh ? '服务盘点' : 'Service inventory', children: <MseInventoryPanel key={snapshot.version} /> }] : []),
      ...(snapshot.name === 'alicloud-privatelink' ? [{ key: 'inventory', label: zh ? '端点盘点' : 'Endpoint inventory', children: <PrivateLinkInventoryPanel key={snapshot.version} /> }] : []),
      { key: 'guide', label: zh ? '接入指南' : 'Guide', children: snapshot.name === 'alicloud-mse' ? <MseInventoryGuide />
        : snapshot.name === 'alicloud-privatelink' ? <PrivateLinkInventoryGuide /> : <CloudGuide /> },
    ]} />}
  </Drawer>;
}
function Configuration({ snapshot, onSaved }: { snapshot: CloudConfig; onSaved: (value: CloudConfig) => void }) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [form] = Form.useForm();
  const scope = useOperationScope();
  const access = useSessionAccess();
  const mode = Form.useWatch(['settings', 'credential_source'], form) as string | undefined;
  const workload = mode === 'ecs-role' || mode === 'oidc-role';
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const save = async () => {
    if (!access.has('alicloud:write')) return;
    const generation = scope.begin();
    if (generation === undefined) return;
    setBusy(true); setError('');
    try {
      const values = await form.validateFields();
      if (!scope.current(generation)) return;
      const merged = configurationSettings(snapshot.name, snapshot.settings, values.settings ?? {}, values.mseNamespaceSelection as MseNamespaceSelection | undefined);
      const settings = apigAuthorizationSettings(snapshot,
        publicationAuthorizationSettings(snapshot, merged, values.mock, values.secrets ?? {}, values.clear ?? []),
        values.mock, values.secrets ?? {}, values.clear ?? []);
      const response = await cloudApi.save(snapshot.name, { enabled: values.enabled, mock: values.mock, settings,
        secrets: values.secrets ?? {}, clear_secrets: values.clear ?? [], expected_version: snapshot.version });
      if (scope.current(generation)) onSaved(response.data);
    } catch (cause) { if (scope.current(generation) && cause instanceof Error) setError(cause.message); }
    finally { if (scope.finish(generation)) setBusy(false); }
  };
  const contexts: Record<string, [string, string, string][]> = {
    'alicloud-agentteams': [['instance_id', 'AgentTeams 实例 ID', 'AgentTeams instance ID']],
    'alicloud-schedulerx3': [['cluster_id', 'SchedulerX3 集群 ID', 'SchedulerX3 cluster ID'], ['app_name', '应用名称', 'Application name']],
    'alicloud-cms': [['group_id', 'CMS 应用分组 ID', 'CMS application group ID']],
  };
  return <Space direction="vertical" size="middle" style={{ width: '100%' }}>
    <Alert type="info" showIcon message={text('凭据加密保存，不会回显', 'Credentials are encrypted and never returned')}
      description={text('空白保留已保存凭据。更换账号、地址、角色或凭据类型时，请重新填写凭据；保存仅校验配置。', 'Blank fields retain saved credentials. Re-enter them when changing account, endpoint, role or credential type. Saving validates configuration only.')} />
    {snapshot.environmentMock && <Alert type="warning" message={text('服务端全局模拟已开启，实际调用不会访问云端', 'Server mock mode is active; calls will not reach the cloud')} />}
    {snapshot.name === 'alicloud-apig' && <Alert type="info" message={text('独立限流策略使用专用五 ID 绑定与发布流程。', 'Independent rate-limit policies use the dedicated five-ID binding and publication workflow.')}
      description={<Space direction="vertical"><span>{text('目标、来源、模式或任何凭据变更会清除旧管理确认。先保存此连接，再到专用绑定页核对并明确重新确认；不会自动发布或初始化。',
        'Target, source, mode or any credential change clears prior management consent. Save this connection, then verify and reconfirm in the dedicated binding page; no publication or initialization is automatic.')}</span>
        <a href="/alicloud?tab=apig-policy" target="_blank" rel="noreferrer">{text('在新标签页打开 APIG 专用发布（保留当前草稿）', 'Open dedicated APIG publication in a new tab (retain this draft)')}</a></Space>} />}
    <Form form={form} layout="vertical" disabled={busy || !access.has('alicloud:write')} initialValues={{ enabled: snapshot.enabled, mock: snapshot.mock,
      mseNamespaceSelection: initialNamespace(snapshot.settings),
      settings: { region_id: 'cn-hangzhou', endpoint_style: 'public', credential_source: 'access-key', duration_seconds: 3600, ...snapshot.settings } }}>
      <Space><Form.Item name="enabled" label={text('启用', 'Enabled')} valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name="mock" label={text('模拟模式', 'Mock mode')} valuePropName="checked"><Switch /></Form.Item></Space>
      <Form.Item name={['settings', 'region_id']} label={text('地域', 'Region')} rules={[{ required: true }]}><Input placeholder="cn-hangzhou" /></Form.Item>
      <Form.Item name={['settings', 'account_id']} label={text('云账号 ID（用于识别）', 'Cloud account ID (label)')}><Input /></Form.Item>
      <Form.Item name={['settings', 'endpoint_style']} label={text('网络入口', 'Network endpoint')}><Select options={[
        { value: 'public', label: text('官方公网接入点', 'Official public endpoint') }, { value: 'private', label: text('官方 VPC 接入点', 'Official VPC endpoint') },
      ]} /></Form.Item>
      <Form.Item name={['settings', 'endpoint']} label={text('自定义服务根地址（选填）', 'Custom service root URL (optional)')}><Input placeholder={snapshot.endpoint} /></Form.Item>
      {contexts[snapshot.name]?.map(([key, cn, en]) => <Form.Item key={key} name={['settings', key]} label={text(cn, en)}><Input /></Form.Item>)}
      {snapshot.name === 'alicloud-mse' && <MseNamespaceFields />}
      {snapshot.name === 'alicloud-mse' && <>
        <Form.Item name={['settings', 'engine_origin']} label={text('Nacos 引擎 origin（专用发布选填）', 'Nacos engine origin (optional for dedicated publication)')}
          rules={[{ validator: (_, value: unknown) => validOptionalEngineOrigin(value) ? Promise.resolve() : Promise.reject(new Error(text('请使用独立 HTTPS origin，不含路径、查询或凭据；HTTP 仅服务端授权的字面 loopback 测试可用。', 'Use a separate HTTPS origin without path, query or credentials; HTTP requires a server-authorized literal loopback test.'))) }]}>
          <Input placeholder="https://your-nacos-engine.example" />
        </Form.Item>
        <Alert type="warning" showIcon message={text('引擎 origin 独立于上面的 OpenAPI 根地址；服务盘点不要求填写。', 'The engine origin is separate from the OpenAPI root above; service inventory does not require it.')}
          description={text('真实启用连接更换引擎地址时，同次填写适用的新凭据，或先明确停用后修改；旧凭据不会用于新目标。目标、来源、模式或凭据变化会清除专用发布的 upsert 授权，保存后返回专用绑定页重新明确确认。',
            'When retargeting an enabled Live connection, supply appropriate new credentials in the same save, or explicitly disable it first. Old credentials are not retained for a new target. Target, source, mode or credential changes clear dedicated-publication upsert authorization; return to Target binding and reconfirm after saving.')} />
      </>}
      {snapshot.name === 'alicloud-privatelink' && <PrivateLinkEndpointFields />}
      <Form.Item name={['settings', 'credential_source']} label={text('凭据类型', 'Credential type')}><Select options={[
        { value: 'ecs-role', label: text('ECS 实例 RAM Role（IMDSv2）', 'ECS instance RAM role (IMDSv2)') },
        { value: 'oidc-role', label: text('Kubernetes OIDC 工作负载身份', 'Kubernetes OIDC workload identity') },
        { value: 'assume-role', label: text('跨账号 AssumeRole（自动更新会话）', 'AssumeRole (automatic session refresh)') },
        { value: 'sts', label: text('已签发的临时 STS', 'Pre-issued temporary STS') },
        { value: 'access-key', label: text('RAM 用户 AccessKey', 'RAM user AccessKey') },
      ]} /></Form.Item>
      {workload && <Alert type="info" showIcon message={text('无需保存长期密钥', 'No stored long-lived keys')}
        description={text('部署端必须用 AGF_CLOUD_WORKLOAD_TENANTS 授权当前租户。ECS 须绑定实例角色；OIDC 须挂载 ALIBABA_CLOUD_OIDC_TOKEN_FILE。自动按到期时间更新临时凭据。', 'The deployment must authorize this tenant through AGF_CLOUD_WORKLOAD_TENANTS. ECS requires an attached instance role; OIDC requires ALIBABA_CLOUD_OIDC_TOKEN_FILE. Temporary credentials refresh before expiration.')} />}
      {mode === 'ecs-role' && <Form.Item name={['settings', 'ecs_role_name']} label={text('ECS 角色名（留空自动发现）', 'ECS role name (blank discovers attached role)')}><Input /></Form.Item>}
      {mode === 'oidc-role' && <Form.Item name={['settings', 'oidc_provider_arn']} label="OIDC Provider ARN"><Input placeholder="acs:ram::1234567890123456:oidc-provider/agf" /></Form.Item>}
      {!workload && Object.entries(secretLabels).map(([key, label]) => <Form.Item key={key} name={['secrets', key]} label={label}>
        <Input.Password autoComplete="new-password" placeholder={snapshot.secretKeys.includes(key) ? text('已保存；留空保留', 'Saved; blank retains value') : text('尚未提供', 'Not provided')} />
      </Form.Item>)}
      {!workload && <><Form.Item name="clear" label={text('清除已保存的凭据', 'Clear stored credentials')}><Checkbox.Group options={snapshot.secretKeys.map(key => ({ value: key, label: secretLabels[key as keyof typeof secretLabels] ?? key }))} /></Form.Item>
        <Form.Item name={['settings', 'expires_at']} label={text('临时 Token 到期时间（RFC3339）', 'Temporary token expiration (RFC3339)')}><Input placeholder="2026-09-20T15:00:00Z" /></Form.Item></>}
      {(mode === 'assume-role' || mode === 'oidc-role') && <>
        <Form.Item name={['settings', 'role_arn']} label="Role ARN" rules={[{ required: true }]}><Input placeholder="acs:ram::1234567890123456:role/agf" /></Form.Item>
        <Form.Item name={['settings', 'role_session_name']} label={text('会话名称', 'Session name')}><Input placeholder="aiguardfabric" /></Form.Item>
        <Form.Item name={['settings', 'duration_seconds']} label={text('会话有效期（秒）', 'Session duration (seconds)')}><InputNumber min={900} max={43200} /></Form.Item>
        {mode === 'assume-role' && <Form.Item name={['settings', 'external_id']} label="External ID"><Input /></Form.Item>}
        <Form.Item name={['settings', 'session_policy']} label={text('进一步限制的会话策略（JSON，选填）', 'Restrictive session policy (optional JSON)')}><Input.TextArea rows={3} /></Form.Item>
        <Form.Item name={['settings', 'sts_endpoint']} label={text('STS 服务根地址（选填）', 'STS service root URL (optional)')}><Input placeholder="https://sts.aliyuncs.com" /></Form.Item>
      </>}
    </Form>
    {error && <Alert type="error" message={error} />}
    <Space><Button type="primary" loading={busy} disabled={!access.has('alicloud:write')} onClick={() => void save()}>{text('保存配置', 'Save configuration')}</Button>
      <Typography.Text type="secondary">{text('当前版本', 'Current version')} {snapshot.version}</Typography.Text></Space>
  </Space>;
}
