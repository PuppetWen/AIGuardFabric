import { useState } from 'react';
import { Alert, Button, Checkbox, Input, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/stores/authStore';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { PreparationError, prepareCallbackPlan, type CallbackPlan, type PreparationErrorCode } from './callbackPlan';
import { SCHEDULER_TASKS } from './tasks';

const errors: Record<PreparationErrorCode, [string, string]> = {
  origin: ['填写完整 HTTPS origin，例如 https://scheduler.example.com:9443。只能是域名/地址和可选端口；不能包含用户名、密码、路径、查询、片段、反斜线或空白。',
    'Enter an HTTPS origin, such as https://scheduler.example.com:9443. Use only host/address and optional port, without credentials, path, query, fragment, backslashes or whitespace.'],
  tenant: ['当前租户 UUID 无效。请先选择实际部署对应的租户，再重新准备。',
    'The current tenant UUID is invalid. Select the tenant used by this deployment, then prepare again.'],
  app: ['填写实际云 HTTP AppId 的规范正 int64 十进制字符串，不允许前导零、符号、溢出、AppName 或令牌。',
    'Enter the actual HTTP AppId as a canonical positive int64 string; no leading zeros, signs, overflow, AppName or token.'],
  kinds: ['至少明确选择一类任务。', 'Explicitly select at least one task.'],
};

export function SchedulerCallbackPreparation() {
  const tenant = useAuthStore(state => state.tenant);
  const generation = useAuthStore(state => state.sessionGeneration);
  return <PreparationForm key={`${tenant?.id ?? ''}:${tenant?.slug ?? ''}:${generation}`} tenantId={tenant?.id ?? ''} />;
}

function PreparationForm({ tenantId }: { tenantId: string }) {
  const { i18n } = useTranslation();
  const language = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh') ? 0 : 1;
  const text = (cn: string, en: string) => language === 0 ? cn : en;
  const scope = useOperationScope();
  const [origin, setOrigin] = useState('');
  const [appId, setAppId] = useState('');
  const [kinds, setKinds] = useState<string[]>([]);
  const [plan, setPlan] = useState<CallbackPlan | null>(null);
  const [error, setError] = useState<PreparationErrorCode | null>(null);
  const [copyStatus, setCopyStatus] = useState<'idle' | 'copied' | 'failed'>('idle');
  const [copyBusy, setCopyBusy] = useState(false);
  const edit = (change: () => void) => {
    if (!scope.reset()) return;
    change(); setPlan(null); setError(null); setCopyStatus('idle');
  };
  const prepare = () => {
    if (!scope.reset()) return;
    setCopyStatus('idle'); setError(null); setPlan(null);
    try { setPlan(prepareCallbackPlan({ origin, tenantId, appId, kinds })); }
    catch (failure) {
      if (failure instanceof PreparationError) setError(failure.code);
      else throw failure;
    }
  };
  const copy = async () => {
    if (!plan) return;
    const operation = scope.begin();
    if (operation === undefined) return;
    setCopyBusy(true); setCopyStatus('idle');
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(JSON.stringify(plan, null, 2));
      if (scope.current(operation)) setCopyStatus('copied');
    } catch {
      if (scope.current(operation)) setCopyStatus('failed');
    } finally {
      if (scope.finish(operation)) setCopyBusy(false);
    }
  };
  return <Space direction="vertical" size="middle" style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('准备云 HTTP 回调配置', 'Prepare cloud HTTP callback configuration')}</Typography.Title>
    <Alert type="warning" showIcon message={text('准备材料，不会注册、启用或执行任务', 'Preparation does not register, enable or execute tasks')}
      description={text('这里只生成非敏感接入材料，所有字段验证均在浏览器本地完成，不访问所填地址。不会保存部署变量或验证连通性；切换租户或登录会话会清空材料。',
        'This generates non-secret setup material with local validation only. It does not contact the supplied address, save deployment variables or verify connectivity. A tenant or sign-in change clears it.')} />
    <div>
      <label htmlFor="scheduler-callback-origin">{text('调度器回调 HTTPS origin', 'Scheduler callback HTTPS origin')}</label>
      <Input id="scheduler-callback-origin" value={origin} disabled={copyBusy} autoComplete="off"
        placeholder="https://scheduler.example.com:9443" onChange={event => edit(() => setOrigin(event.target.value))} />
      <Typography.Text type="secondary">{text('填写反向代理的 HTTPS origin；它应转发到调度服务 9101。平台 API 地址和云 OpenAPI endpoint 是不同地址。',
        'Use the HTTPS reverse-proxy origin that routes to scheduler port 9101. The platform API address and cloud OpenAPI endpoint are separate addresses.')}</Typography.Text>
    </div>
    <div>
      <label htmlFor="scheduler-callback-tenant">{text('当前部署租户 UUID', 'Current deployment tenant UUID')}</label>
      <Input id="scheduler-callback-tenant" value={tenantId} readOnly />
      <Typography.Text type="secondary">{text('如部署属于另一租户，请先切换顶部租户。此 UUID 必须与服务 Key 的实际租户一致；不会写进回调 URL。',
        'If the deployment belongs to another tenant, select it first. This UUID must match the service key tenant; it is not placed in callback URLs.')}</Typography.Text>
    </div>
    <div>
      <label htmlFor="scheduler-callback-app">{text('云 HTTP 应用实际 AppId', 'Actual cloud HTTP application AppId')}</label>
      <Input id="scheduler-callback-app" value={appId} disabled={copyBusy} autoComplete="off"
        onChange={event => edit(() => setAppId(event.target.value))} />
      <Typography.Text type="secondary">{text('AppId 必须与部署 CALLBACK_APP_ID 和云发送的 header 完全一致；连接设置的 AppName / ClusterId 不能替代它。',
        'AppId must exactly match deployed CALLBACK_APP_ID and the cloud header. Connection AppName / ClusterId cannot replace it.')}</Typography.Text>
    </div>
    <fieldset disabled={copyBusy} style={{ border: 0, padding: 0 }}>
      <legend>{text('明确选择要准备的任务', 'Select tasks to prepare')}</legend>
      <Checkbox.Group value={kinds} disabled={copyBusy} onChange={values => edit(() => setKinds(values.map(String)))}>
        <Space direction="vertical">{SCHEDULER_TASKS.map(task => <Checkbox key={task.kind} value={task.kind}>
          {task.kind} — {task.title[language]}
        </Checkbox>)}</Space>
      </Checkbox.Group>
    </fieldset>
    <Button onClick={prepare} disabled={copyBusy}>{text('生成回调准备材料', 'Generate callback preparation')}</Button>
    {error && <Alert type="error" showIcon message={errors[error][language]} />}
    {plan && <>
      <Alert type="info" showIcon message={text(`已准备 ${plan.tasks.length} 类；登记和部署状态尚未验证`,
        `${plan.tasks.length} tasks prepared; registration and deployment remain unverified`)}
        description={text('材料不包含任何可用令牌。requiredSecretReferences 是部署管理员必须提供的 SecretRef 要求，不能原样作为凭据运行。请按上述步骤和任务说明完成云控制台及部署配置。',
          'This contains no usable token. requiredSecretReferences describes secrets the deployment administrator must supply; it cannot be run as credentials. Complete cloud-console and deployment setup using the steps and task details above.')} />
      <Input.TextArea aria-label={text('非敏感回调准备材料', 'Non-secret callback preparation')} value={JSON.stringify(plan, null, 2)} readOnly rows={14} />
      <Button onClick={() => void copy()} loading={copyBusy}>{text('复制非敏感准备材料', 'Copy non-secret preparation')}</Button>
    </>}
    {copyStatus === 'copied' && <Alert type="success" message={text('已复制准备材料；没有注册或执行任务。', 'Preparation copied; no tasks were registered or executed.')} />}
    {copyStatus === 'failed' && <Alert type="warning" message={text('剪贴板不可用或写入失败。请手动选择上方材料复制；材料仍保留。',
      'Clipboard access is unavailable or failed. Select and copy the material above manually; it remains available.')} />}
  </Space>;
}
