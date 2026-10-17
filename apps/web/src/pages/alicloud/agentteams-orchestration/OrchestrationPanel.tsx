import { Alert, Button, Collapse, Space, Spin, Typography } from 'antd';
import Panel from '@/components/Panel';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { DefinitionEditor } from './DefinitionEditor';
import { OrchestrationGuide } from './OrchestrationGuide';
import { OrchestrationPreview } from './OrchestrationPreview';
import { OrchestrationReceipt } from './OrchestrationReceipt';
import { SavedDefinitions } from './SavedDefinitions';
import { useText } from './text';
import { useOrchestration } from './useOrchestration';

export default function OrchestrationPanel() {
  const tenant = useAuthStore(state => state.tenant), generation = useAuthStore(state => state.sessionGeneration);
  return <Content key={`${tenant?.id}:${tenant?.slug}:${generation}`} />;
}
function Content() {
  const t = useText(), access = useSessionAccess();
  const canRead = !access.isLoading && access.has('alicloud:read');
  const canWrite = canRead && access.has('platform:admin') && access.has('alicloud:write');
  const flow = useOrchestration(canRead, canWrite);
  if (access.isLoading) return <Spin />;
  if (!canRead) return <Alert type="info" message={t('读取需要 alicloud:read', 'Reading requires alicloud:read')} />;
  return <Panel title={t('应用所有的 AgentTeams 编排定义', 'Application-owned AgentTeams orchestration definitions')}>
    <Space direction="vertical" style={{ width: '100%' }}>
      <Alert key="boundary" type="warning" message={t('仅阶段一 Mock：本地 DAG 声明与应用所有接收端，厂商 DAG 未提供；任务/消费者执行未知。',
        'Stage-one Mock only: local DAG declarations and an application-owned receiver. Vendor DAGs are not provided; task and consumer execution remain unknown.')} />
      <Collapse key="guide" items={[{ key: 'orchestration-guide', label: t('编排定义与三种接入模式指南', 'Orchestration and three onboarding modes guide'), children: <OrchestrationGuide /> }]} />
      {flow.error && <Alert key="error" type="error" message={flow.error} description={t('草稿与旧基线保持；不会自动采用版本或重发写入。', 'Draft and original baseline are retained; no automatic adoption or repeat write.')} />}
      <Button key="refresh" loading={flow.loading} onClick={() => void flow.refresh()}>{t('重新读取当前状态比较（GET，保留草稿）', 'Reload current state to compare (GET, keep draft)')}</Button>
      <div key="receipt"><OrchestrationReceipt flow={flow} /></div>
      {flow.data && <div key="current"><Space direction="vertical" style={{ width: '100%' }}>
        <Typography.Text>{t('存储', 'Storage')}: {flow.data.durable ? t('数据库持久', 'Database durable') : t('进程内存', 'Process memory')}; {t('永久请求', 'Permanent intents')}: {flow.data.intentCount}/{flow.data.limits.maxIntents}</Typography.Text>
        {!flow.data.modeSupported && <Alert type="info" message={t('新提交需要启用的完整 Mock AgentTeams 盘点。停用或 Live 时仍可读取原回执。', 'New commits require enabled complete Mock AgentTeams inventory. Original receipts remain readable when disabled or in Live mode.')} />}
        {!canWrite && <Alert type="info" message={t('只读。提交需要管理员用户会话及 platform:admin + alicloud:read/write。', 'Read-only. Committing requires an administrator user session with platform:admin and alicloud:read/write.')} />}
        <SavedDefinitions records={flow.data.records} />
        <DefinitionEditor flow={flow} canWrite={canWrite} /><OrchestrationPreview flow={flow} />
      </Space></div>}
    </Space>
  </Panel>;
}
