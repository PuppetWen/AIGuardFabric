import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';

import { Button, Space, Tabs, message } from 'antd';
import { ReloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons';

import { api, useApiQuery } from '@/api/client';
import { PageHeader } from '@/components/DataState';

import { BindingsPanel } from './alicloud/BindingsPanel';
import { CrossCallsPanel } from './alicloud/CrossCallsPanel';
import { SelfCheckPanel } from './alicloud/SelfCheckPanel';
import { TeamMembersPanel } from './alicloud/TeamMembersPanel';
import { TeamTable } from './alicloud/TeamTable';
import CloudConnections from './alicloud/CloudConnections';
import AgentTeamsAuditPanel from './alicloud/AgentTeamsAuditPanel';
import WorkerQuotasPanel from './alicloud/WorkerQuotasPanel';
import TeamManagementPanel from './alicloud/TeamManagementPanel';
import MseInventoryPanel from './alicloud/mse/MseInventoryPanel';
import MseConfigPublicationPanel from './alicloud/mse-config-publication/MseConfigPublicationPanel';
import PrivateLinkInventoryPanel from './alicloud/privatelink/PrivateLinkInventoryPanel';
import ApigPolicyPublicationPanel from './alicloud/apig-policy-publication/ApigPolicyPublicationPanel';
import SchedulerNativePanel from './alicloud/scheduler-native/SchedulerNativePanel';
import TaskHandlingPanel from './alicloud/task-handling/TaskHandlingPanel';
import RoleMappingPanel from './alicloud/agentteams-role-mapping/RoleMappingPanel';
import OrchestrationPanel from './alicloud/agentteams-orchestration/OrchestrationPanel';
import SchedulerManagedJobsPanel from './alicloud/scheduler-managed/SchedulerManagedJobsPanel';
import CmsQueuePanel from './alicloud/cms-queue/CmsQueuePanel';
import ApigConfigurationPublicationPanel from './alicloud/apig-configuration-publication/ApigConfigurationPublicationPanel';
import PrivateLinkProvisioningPanel from './alicloud/privatelink-provisioning/PrivateLinkProvisioningPanel';

export default function AliCloudPage() {
  const { t, i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const [params, setParams] = useSearchParams();
  const requestedTab = params.get('tab');
  const activeTab = requestedTab && ['audit', 'quotas', 'teams', 'mse', 'mse-config', 'privatelink', 'apig-policy', 'scheduler-native', 'task-handling', 'role-mapping', 'agentteams-orchestration', 'scheduler-managed', 'cms-queue', 'apig-config', 'privatelink-provisioning'].includes(requestedTab) ? requestedTab : 'inventory';
  const [selectedTeamId, setSelectedTeamId] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  const teams = useApiQuery('agentteams', () => api.agentTeams());
  const crossCalls = useApiQuery('cross-team-calls', () => api.crossTeamCalls());
  const bindings = useApiQuery('service-bindings', () => api.serviceBindings());
  const selfCheck = useApiQuery('self-check', () => api.selfCheck());

  const teamList = useMemo(() => teams.data?.data ?? [], [teams.data]);
  const selectedTeam = useMemo(
    () => teamList.find((team) => team.id === selectedTeamId) ?? teamList[0] ?? null,
    [selectedTeamId, teamList],
  );

  const checkItems = selfCheck.data?.data ?? [];
  const summary = {
    pass: checkItems.filter((item) => item.result === 'pass').length,
    warn: checkItems.filter((item) => item.result === 'warn').length,
    fail: checkItems.filter((item) => item.result === 'fail').length,
  };

  const runSelfCheck = async (): Promise<void> => {
    setChecking(true);
    try {
      const refreshed = await selfCheck.refetch();
      if (refreshed.error) throw refreshed.error;
      const items = refreshed.data?.data ?? [];
      message.success(
        t('alicloud.selfcheck.done', {
          pass: items.filter(item => item.result === 'pass').length,
          warn: items.filter(item => item.result === 'warn').length,
          fail: items.filter(item => item.result === 'fail').length,
        }),
      );
    } catch (cause) {
      message.error(String(cause));
    } finally {
      setChecking(false);
    }
  };

  return (
    <>
      <PageHeader
        title={t('alicloud.title')}
        subtitle={t('alicloud.subtitle')}
        actions={activeTab === 'inventory' ?
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => {
              void teams.refetch(); void crossCalls.refetch(); void bindings.refetch(); void selfCheck.refetch();
            }}>
              {t('common.refresh')}
            </Button>
            <Button
              type="primary"
              icon={<SafetyCertificateOutlined />}
              loading={checking}
              onClick={() => void runSelfCheck()}
            >
              {t('alicloud.selfcheck.run')}
            </Button>
          </Space> : undefined
        }
      />

      <Space direction="vertical" size={14} style={{ width: '100%' }}>
        <CloudConnections />
        <Tabs style={{ width: '100%' }} activeKey={activeTab} onChange={tab => setParams(previous => {
          const next = new URLSearchParams(previous);
          next.set('tab', tab);
          return next;
        })} items={[
          {
            key: 'inventory', label: zh ? '团队盘点与指标' : 'Team inventory and metrics',
            children: <Space direction="vertical" size={14} style={{ width: '100%' }}>
              <TeamTable loading={teams.isLoading} error={teams.error} teamList={teamList} onSelectTeam={setSelectedTeamId}
                onManageTeam={name => setParams(previous => { const next = new URLSearchParams(previous);
                  next.set('tab', 'teams'); next.set('team', name); next.delete('request_id'); return next; })} />
              {selectedTeam ? <TeamMembersPanel team={selectedTeam} /> : null}
              <CrossCallsPanel loading={crossCalls.isLoading} error={crossCalls.error} calls={crossCalls.data?.data ?? []} />
              <BindingsPanel loading={bindings.isLoading} error={bindings.error} bindings={bindings.data?.data ?? []} />
              <SelfCheckPanel loading={selfCheck.isLoading} error={selfCheck.error} items={checkItems}
                summary={summary} checking={checking} onRun={() => void runSelfCheck()} />
            </Space>,
          },
          { key: 'audit', label: zh ? '消息与调用审计' : 'Messages and call audit', children: <AgentTeamsAuditPanel teams={teamList} /> },
          { key: 'task-handling', label: zh ? '错误观测与人工处理' : 'Errors and operator handling', children: <TaskHandlingPanel /> },
          { key: 'role-mapping', label: zh ? 'Role 权限映射' : 'Role permission mapping', children: <RoleMappingPanel /> },
          { key: 'agentteams-orchestration', label: zh ? '编排定义' : 'Orchestration definitions', children: <OrchestrationPanel /> },
          { key: 'quotas', label: zh ? 'Worker 配额治理' : 'Worker quota governance', children: <WorkerQuotasPanel /> },
          { key: 'teams', label: t('teamManagement.title'), children: <TeamManagementPanel /> },
          { key: 'mse', label: zh ? 'MSE 服务盘点' : 'MSE service inventory', children: <MseInventoryPanel /> },
          { key: 'mse-config', label: zh ? 'MSE 配置发布' : 'MSE configuration publication', children: <MseConfigPublicationPanel /> },
          { key: 'privatelink', label: zh ? 'PrivateLink 端点盘点' : 'PrivateLink endpoint inventory', children: <PrivateLinkInventoryPanel /> },
          { key: 'apig-policy', label: zh ? 'APIG 策略发布' : 'APIG policy publication', children: <ApigPolicyPublicationPanel /> },
          { key: 'scheduler-native', label: zh ? 'Scheduler 任务接入' : 'Scheduler job connection', children: <SchedulerNativePanel /> },
          { key: 'scheduler-managed', label: zh ? 'Scheduler 受管任务' : 'Scheduler managed jobs', children: <SchedulerManagedJobsPanel /> },
          { key: 'cms-queue', label: zh ? 'CMS 持久补传队列' : 'CMS durable delivery queue', children: <CmsQueuePanel /> },
          { key: 'apig-config', label: zh ? 'APIG 配置与发布' : 'APIG configuration and publication', children: <ApigConfigurationPublicationPanel /> },
          { key: 'privatelink-provisioning', label: zh ? 'PrivateLink 创建与接纳' : 'PrivateLink creation and acceptance', children: <PrivateLinkProvisioningPanel /> },
        ]} />
      </Space>
    </>
  );
}
