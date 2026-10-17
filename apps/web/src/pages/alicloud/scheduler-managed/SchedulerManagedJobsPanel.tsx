import { Alert, Button, Collapse, Input, Select, Space, Spin, Typography } from 'antd';
import Panel from '@/components/Panel';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { ManagedDefinitions } from './ManagedDefinitions';
import { ManagedEditor } from './ManagedEditor';
import { ManagedGuide } from './ManagedGuide';
import { ManagedHistory } from './ManagedHistory';
import { ManagedObservation } from './ManagedObservation';
import { ManagedPreview } from './ManagedPreview';
import { ManagedReceipt } from './ManagedReceipt';
import { useManagedJobs } from './useManagedJobs';
import { useText, uuid } from './text';
export default function SchedulerManagedJobsPanel() {
  const tenant = useAuthStore(state => state.tenant), generation = useAuthStore(state => state.sessionGeneration);
  return <Content key={`${tenant?.id}:${tenant?.slug}:${generation}`} />;
}
function Content() {
  const t = useText(), access = useSessionAccess(), canRead = !access.isLoading && access.has('alicloud:read');
  const permitted = canRead && access.has('alicloud:write') && access.has('platform:admin');
  const flow = useManagedJobs(canRead, permitted), canManage = permitted && flow.data?.canManage === true;
  if (access.isLoading) return <Spin />;
  if (!canRead) return <Alert type="info" message={t('查看受管任务需要 alicloud:read', 'Managed jobs require alicloud:read')} />;
  return <Panel title={t('SchedulerX3 受管六任务', 'SchedulerX3 managed six jobs')}><Space direction="vertical" style={{ width: '100%' }}>
    <Alert key="boundary" type="warning" showIcon message={t('云注册/部署/消费者未验证；每次只提交一个明确动作', 'Cloud registration/deployment/consumers are unverified; submit one explicit action at a time')}
      description="callbackBindingEnforced=false · deploymentVerified=unknown · consumerApplied=unknown · cloudCasAvailable=false" />
    <Collapse key="guide" items={[{ key: 'guide', label: t('受管六任务操作指南', 'Managed six-job guide'), children: <ManagedGuide /> }]} />
    <Button key="reload" loading={flow.loading} onClick={() => void flow.refresh()}>{t('GET 重新加载比较（保留草稿）', 'GET reload to compare (keep draft)')}</Button>
    <div key="original-controls"><Space direction="vertical">
      <Typography.Text>{t('原编号只读恢复：输入不会自动请求', 'Read-only recovery by original ID: typing never requests automatically')}</Typography.Text>
      <Space wrap><Select aria-label={t('原编号用途', 'Original ID purpose')} value={flow.purpose} onChange={value => flow.changeRequest(flow.requestId, value)}
        options={[{ value: 'apply', label: t('原修改回执', 'Original change receipt') }, { value: 'preview', label: t('原预览', 'Original preview') }]} style={{ width: 230 }} />
        <Input aria-label={t('原受管请求编号', 'Original managed request ID')} value={flow.requestId} style={{ width: 360 }} onChange={event => flow.changeRequest(event.target.value)} />
        <Button loading={flow.reading} disabled={!uuid(flow.requestId) || flow.reading} onClick={() => void flow.readOriginal()}>{t('GET 读取原编号', 'GET read original ID')}</Button>
      </Space>
    </Space></div>
    {flow.error && <Alert key="error" type="error" message={flow.error} description={t('草稿、基线与原意图保留。重新加载只比较；不确定时读取原编号或显式本地恢复，绝不自动重发。',
      'Draft, baseline and original intent remain. Reload only compares; read the original ID or explicitly recover locally after uncertainty, never automatically redispatch.')} />}
    {flow.intent && <div key="intent"><Typography.Text>{t('保留的原意图', 'Retained original intent')}: {flow.intent.purpose} · {flow.intent.id} · {flow.intent.state}</Typography.Text>
      {flow.intentLocked && <Alert type="warning" message={t('原意图尚未确定，写入锁定；404 不允许重发。GET 可在请求等待中读取。',
        'The original intent is uncertain and new writes are locked; 404 never permits redispatch. GET remains available while the request is in flight.')} />}
      <Button disabled={flow.busy || flow.intentLocked} onClick={flow.release}>{t('明确开始另一个独立动作（保留草稿）', 'Explicitly start another separate action (keep draft)')}</Button>
    </div>}
    <ManagedPreview key={flow.preview?.id ?? 'no-preview'} flow={flow} canManage={canManage} />
    <ManagedReceipt key="operation" flow={flow} canManage={canManage} />
    {flow.data && <div key="state"><Space direction="vertical" style={{ width: '100%' }}>
      {!canManage && <Alert type="info" message={t('管理需要管理员 User + platform:admin、alicloud:read/write；API Key 不可管理。只读 GET 可核查历史。',
        'Management requires an administrator User with platform:admin and alicloud:read/write; API Keys cannot manage. Read-only GET can inspect history.')} />}
      <ManagedObservation key={`${flow.nativeState?.sourceTarget?.fingerprint}:${flow.nativeState?.sourceTarget?.configurationVersion}`} flow={flow} canManage={canManage} />
      <ManagedEditor flow={flow} canManage={canManage} />
      <ManagedDefinitions flow={flow} />
      <ManagedHistory flow={flow} canManage={canManage} />
    </Space></div>}
  </Space></Panel>;
}
