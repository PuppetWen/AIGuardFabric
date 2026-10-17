import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Collapse, Input, Select, Space } from 'antd';
import { api, useApiQuery } from '@/api/client';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { DefinitionDetail } from '@/components/DefinitionDetail';
import { PageHeader } from '@/components/DataState';
import { CampaignTable } from './redteam/CampaignTable';
import { CampaignWizard } from './redteam/CampaignWizard';
import { CampaignDetailDrawer } from './redteam/CampaignDetailDrawer';
import { RedteamGuide } from './redteam/RedteamGuide';
import { AgentTargetsPanel } from './redteam/AgentTargetsPanel';
import { McpTargetsPanel } from './redteam/McpTargetsPanel';
import { MultiTargetPanel } from './redteam/multi-target/MultiTargetPanel';

export default function RedTeamPage() {
  const tenant = useAuthStore(state => state.tenant?.id);
  const session = useAuthStore(state => state.sessionGeneration);
  return <CampaignPage key={`${tenant}:${session}`} />;
}
function CampaignPage() {
  const { t, i18n } = useTranslation(); const zh = i18n.language.startsWith('zh');
  const access = useSessionAccess(); const canExecute = access.has('redteam:execute');
  const canViewTargets = access.has('agents:read');
  const canConfigureTargets = canExecute && canViewTargets && access.has('agents:write');
  const canViewMcpTargets = access.has('mcps:read');
  const canConfigureMcpTargets = canExecute && canViewMcpTargets && access.has('mcps:write');
  const [params, setParams] = useSearchParams(); const selectedId = params.get('campaign');
  const [wizard, setWizard] = useState(false); const [page, setPage] = useState(1);
  const [state, setState] = useState(''); const [q, setQ] = useState('');
  const campaigns = useApiQuery('campaigns', () => api.campaigns({ page, pageSize: 10, sortBy: 'createdAt', sortOrder: 'desc', state, q }),
    { key: [page, state, q], refetchInterval: 3000 });
  const select = (id: string | null) => setParams(previous => { const next = new URLSearchParams(previous); if (id) next.set('campaign', id); else next.delete('campaign'); return next; });
  return <>
    <DefinitionDetail kind="testCase" />
    <PageHeader title={t('redteam.title')} subtitle={t('redteam.subtitle')} actions={<Space>
      <Button onClick={() => void campaigns.refetch()}>{t('common.refresh')}</Button>
      {canExecute && <Button type="primary" onClick={() => setWizard(true)}>{zh ? '发起红队战役' : 'Launch red-team campaign'}</Button>}
    </Space>} />
    <Space direction="vertical" style={{ width: '100%' }} size="large">
      <Alert type="info" showIcon message={zh ? '执行状态与 CI 判定分别显示' : 'Execution status and CI verdict are separate'} description={zh
        ? '“已完成”表示全部用例执行完毕；CI 根据所选严重等级判定。模拟战役不测试真实资产，也不计入总览的真实攻击成功率。'
        : 'Completed means every case ran. CI evaluates the chosen severity threshold. Simulator runs do not test actual assets and are excluded from the overview real attack success rate.'} />
      <Collapse items={[
        ...(canViewTargets && canViewMcpTargets ? [{ key: 'multi-target', label: zh ? '多目标只读链路' : 'Multiple target read-only chain', children: <MultiTargetPanel canExecute={canExecute} canManage={canExecute && access.has('platform:admin')} /> }] : []),
        { key: 'guide', label: zh ? '操作与 CI 接入指南' : 'Operation and CI guide', children: <RedteamGuide /> },
        ...(canViewTargets ? [{ key: 'targets', label: zh ? 'Agent 目标配置' : 'Agent target configuration', children: <AgentTargetsPanel canConfigure={canConfigureTargets} /> }] : []),
        ...(canViewMcpTargets ? [{ key: 'mcp-targets', label: zh ? 'MCP 目标配置' : 'MCP target configuration', children: <McpTargetsPanel canConfigure={canConfigureMcpTargets} /> }] : []),
      ]} />
      <Space wrap>
        <Input.Search allowClear value={q} placeholder={zh ? '名称或 ID' : 'Name or ID'} onChange={event => { setQ(event.target.value); setPage(1); }} />
        <Select value={state} style={{ width: 160 }} onChange={value => { setState(value); setPage(1); }} options={[
          ['', zh ? '全部状态' : 'All states'], ['queued', zh ? '排队' : 'Queued'], ['running', zh ? '执行中' : 'Running'],
          ['completed', zh ? '已完成' : 'Completed'], ['failed', zh ? '失败' : 'Failed'], ['cancelled', zh ? '已取消' : 'Cancelled'],
        ].map(([value, label]) => ({ value, label }))} />
      </Space>
      <CampaignTable loading={campaigns.isLoading} error={campaigns.error} campaigns={campaigns.data?.data.items ?? []}
        onSelect={select} page={page} total={campaigns.data?.data.total ?? 0} onPage={setPage} />
    </Space>
    {wizard && canExecute && <CampaignWizard open canUseAgentTarget={canViewTargets} canUseMcpTarget={canViewMcpTargets} onClose={() => setWizard(false)} onSubmitted={id => { select(id); setPage(1); void campaigns.refetch(); }} />}
    {selectedId && <CampaignDetailDrawer key={selectedId} selectedId={selectedId} canExecute={canExecute}
      canUseAgentTarget={canViewTargets} canUseMcpTarget={canViewMcpTargets} onClose={() => select(null)} onRetest={select} />}
  </>;
}
