import { Alert, Button, Collapse, Space, Spin } from 'antd';
import Panel from '@/components/Panel';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { useRoleMapping } from './useRoleMapping';
import { useRoleText } from './text';
import { RoleDraft } from './RoleDraft';
import { RoleTable } from './RoleTable';
import { RoleReceipt } from './RoleReceipt';
import { RoleMappingGuide } from './RoleMappingGuide';

export default function RoleMappingPanel() {
  const tenant = useAuthStore(state => state.tenant), generation = useAuthStore(state => state.sessionGeneration);
  return <Content key={`${tenant?.id}:${tenant?.slug}:${generation}`} />;
}
function Content() {
  const t = useRoleText(), access = useSessionAccess();
  const canRead = !access.isLoading && access.has('platform:admin') && access.has('alicloud:read');
  const canWrite = canRead && access.has('assets:write'), flow = useRoleMapping(canRead, canWrite);
  if (access.isLoading) return <Spin />;
  if (!canRead) return <Alert type="info" message={t('查看需要 platform:admin + alicloud:read', 'Reading requires platform:admin + alicloud:read')} />;
  return <Panel title={t('AgentTeams 平台角色权限约束', 'AgentTeams platform Role permission constraints')}>
    <Space direction="vertical" style={{ width: '100%' }}>
      <Alert key="boundary" type="warning" message={t('真实平台角色权限与原 Key scopes 取交集；CloudRole 是观察字段，不是认证或授权。',
        'Actual platform Role permissions intersect original Key scopes; CloudRole is an observation, not authentication or a grant.')} />
      <Collapse key="guide" items={[{ key: 'role-guide', label: t('角色约束操作指南', 'Role constraint operating guide'), children: <RoleMappingGuide /> }]} />
      {flow.error && <Alert key="error" type="error" message={flow.error} description={t('草稿/版本/请求编号保留。读取原回执或 GET 比较；不会自动改版本重发。',
        'Draft, revision and request ID are retained. Read the original receipt or compare via GET; no automatic revision change or repeat write.')} />}
      <Button key="refresh" loading={flow.loading} disabled={flow.busy} onClick={() => void flow.refresh()}>{t('重新加载角色与成员比较（GET，保留草稿）', 'Reload Roles and members to compare (GET, keep draft)')}</Button>
      <div key="receipt"><RoleReceipt flow={flow} /></div>
      {flow.data && <div key="current"><Space direction="vertical" style={{ width: '100%' }}>
        {!flow.data.catalogAvailable && <Alert type="info" message={t('离线模式没有真实 Role UUID 目录；新增映射未实现，未纳管 Key 保持原权限。',
          'Offline mode has no actual Role UUID catalog. New mappings are unavailable; unmanaged Keys retain their original grants.')} />}
        {!canWrite && <Alert type="info" message={t('只读：提交采用或停用另需 assets:write 与管理员用户会话。',
          'Read-only: adoption or disable also requires assets:write and an administrator user session.')} />}
        <RoleDraft flow={flow} canWrite={canWrite} /><RoleTable flow={flow} canWrite={canWrite} />
      </Space></div>}
    </Space>
  </Panel>;
}
