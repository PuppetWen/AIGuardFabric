import { Alert, Button, Collapse, Input, Space, Spin, Typography } from 'antd';
import { useSessionAccess } from '@/api/sessionAccess';
import Panel from '@/components/Panel';
import { useAuthStore } from '@/stores/authStore';
import { useSchedulerNative } from './useSchedulerNative';
import { useSchedulerText, uuid } from './text';
import { SchedulerObserve } from './SchedulerObserve';
import { SchedulerBindings } from './SchedulerBindings';
import { SchedulerHistory } from './SchedulerHistory';
import { SchedulerNativeGuide } from './SchedulerNativeGuide';

export default function SchedulerNativePanel() {
  const tenant = useAuthStore(state => state.tenant), generation = useAuthStore(state => state.sessionGeneration);
  return <Content key={`${tenant?.id}:${tenant?.slug}:${generation}`} />;
}
function Content() {
  const t = useSchedulerText(), access = useSessionAccess();
  const canRead = access.has('alicloud:read'), canWrite = canRead && access.has('alicloud:write');
  const flow = useSchedulerNative(canRead, canWrite), data = flow.data;
  if (access.isLoading) return <Spin />;
  if (!canRead) return <Alert type="info" message={t('查看此页面需要 alicloud:read', 'This page requires alicloud:read')} />;
  return <Panel title={t('SchedulerX3 原生观察与本地关联', 'SchedulerX3 native observations and local associations')}>
    <Space direction="vertical" style={{ width: '100%' }}>
      <Alert key="boundary" type="warning" showIcon message={t('回调绑定尚未强制执行；云注册、部署与可达性未知', 'Callback binding is not enforced; cloud registration, deployment and reachability are unknown')}
        description="callbackBindingEnforced=false · deploymentVerified=unknown · callbackConfigured=unknown" />
      <Collapse key="guide" items={[{ key: 'native-guide', label: t('原生观察与本地关联操作指南', 'Native observation and association guide'), children: <SchedulerNativeGuide /> }]} />
      {flow.error && <Alert key="error" type="error" showIcon message={flow.error} description={t('草稿与原编号保留。先检查原因，读取原编号或重新加载比较；不会自动重发业务请求。',
        'The draft and original ID are retained. Check the cause, read the original ID or reload to compare; business requests are never automatically repeated.')} />}
      <Button key="refresh" loading={flow.loading} onClick={() => void flow.refresh()}>{t('重新加载本地状态（保留草稿）', 'Reload local state (keep draft)')}</Button>
      <div key="receipt-controls">
        <Typography.Text>{t('原观察编号：读取与分页只使用 GET', 'Original observation ID: reads and paging use GET only')}</Typography.Text>
        <Space wrap>
          <Input aria-label={t('原观察编号', 'Original observation ID')} value={flow.requestId} style={{ width: 350 }} onChange={event => flow.changeRequest(event.target.value)} />
          <Button loading={flow.reading} disabled={!uuid(flow.requestId) || flow.reading} onClick={() => void flow.readReceipt()}>{t('读取原观察回执', 'Read original observation receipt')}</Button>
        </Space>
      </div>
      {data && <div key="loaded-state">
        <Space direction="vertical" style={{ width: '100%' }}>
          {!canWrite && <Alert type="info" message={t('只读模式：可手动观察与读取回执；初始化、关联和归档需要 alicloud:write。',
            'Read-only mode: manual observations and receipt reads are available; initialization, associations and archive require alicloud:write.')} />}
          <SchedulerObserve key={`${data.sourceTarget?.fingerprint}:${data.sourceTarget?.configurationVersion}`} flow={flow} canWrite={canWrite} />
          <SchedulerBindings flow={flow} canWrite={canWrite} />
          <SchedulerHistory flow={flow} canWrite={canWrite} />
        </Space>
      </div>}
    </Space>
  </Panel>;
}
