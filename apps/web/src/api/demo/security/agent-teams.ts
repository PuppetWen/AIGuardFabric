import type {
  AgentTeam,
  AgentTeamMember,
  CrossTeamCall,
  ServiceBinding,
  TeamDagNode,
} from '@/types/domain';

import { agoDays, seeded } from '../../../utils/time';

/* ------------------------------------------------------------------ */
/* Alibaba Cloud AgentTeams                                            */
/* ------------------------------------------------------------------ */

const teamMembers = (team: string, count: number): AgentTeamMember[] => {
  const roles: AgentTeamMember['role'][] = ['orchestrator', 'worker', 'critic', 'retriever', 'tool-agent'];
  const models = ['qwen-max-2025-01-25', 'qwen-plus-latest', 'deepseek-chat', 'Qwen2.5-72B-Instruct'];
  const rand = seeded(team.length * 131 + count);
  return Array.from({ length: count }, (_, index) => ({
    id: `${team}-m${index + 1}`,
    name: `${team}-${(roles[index % roles.length] as string)}-${index + 1}`,
    role: roles[index % roles.length] as AgentTeamMember['role'],
    model: models[index % models.length] as string,
    status: (['active', 'active', 'idle', 'offline'] as const)[Math.floor(rand() * 4)] as
      | 'active'
      | 'idle'
      | 'offline',
    invocations24h: Math.round(120 + rand() * 9_800),
  }));
};

const teamDag = (members: AgentTeamMember[]): TeamDagNode[] =>
  members.map((member, index) => ({
    id: member.id,
    label: member.name,
    role: member.role,
    dependsOn:
      member.role === 'orchestrator'
        ? []
        : members
            .slice(0, index)
            .filter((candidate) => candidate.role === 'orchestrator' || candidate.role === 'retriever')
            .map((candidate) => candidate.id),
  }));

function buildTeam(
  id: string,
  name: string,
  workspaceId: string,
  region: string,
  memberCount: number,
  crossTeamCalls24h: number,
  riskScore: number,
  createdDays: number,
): AgentTeam {
  const members = teamMembers(id, memberCount);
  return {
    id,
    name,
    workspaceId,
    region,
    memberCount,
    members,
    dag: teamDag(members),
    crossTeamCalls24h,
    riskScore,
    createdAt: agoDays(createdDays),
  };
}

export const demoAgentTeams: AgentTeam[] = [
  buildTeam('team-customer-ops', '客服运营团队', 'ws-acme-prod-01', 'cn-hangzhou', 6, 1_284, 82, 120),
  buildTeam('team-risk-decision', '风控决策团队', 'ws-acme-prod-01', 'cn-hangzhou', 5, 642, 74, 210),
  buildTeam('team-research', '投研分析团队', 'ws-acme-prod-02', 'cn-shanghai', 7, 318, 58, 88),
  buildTeam('team-content', '内容生产团队', 'ws-acme-prod-02', 'cn-shanghai', 4, 96, 41, 60),
  buildTeam('team-ops', '智能运维团队', 'ws-acme-prod-03', 'cn-beijing', 5, 2_140, 91, 150),
  buildTeam('team-compliance', '合规审计团队', 'ws-acme-prod-03', 'cn-beijing', 3, 24, 29, 45),
];

export const demoCrossTeamCalls: CrossTeamCall[] = [
  {
    id: 'ctc-001',
    callerTeam: '客服运营团队',
    calleeTeam: '风控决策团队',
    calleeAgent: 'team-risk-decision-orchestrator-1',
    count24h: 842,
    authorized: true,
    sensitiveData: true,
  },
  {
    id: 'ctc-002',
    callerTeam: '智能运维团队',
    calleeTeam: '客服运营团队',
    calleeAgent: 'team-customer-ops-tool-agent-5',
    count24h: 1_204,
    authorized: false,
    sensitiveData: true,
  },
  {
    id: 'ctc-003',
    callerTeam: '内容生产团队',
    calleeTeam: '投研分析团队',
    calleeAgent: 'team-research-retriever-4',
    count24h: 96,
    authorized: true,
    sensitiveData: false,
  },
  {
    id: 'ctc-004',
    callerTeam: '智能运维团队',
    calleeTeam: '合规审计团队',
    calleeAgent: 'team-compliance-critic-3',
    count24h: 18,
    authorized: false,
    sensitiveData: false,
  },
  {
    id: 'ctc-005',
    callerTeam: '客服运营团队',
    calleeTeam: '内容生产团队',
    calleeAgent: 'team-content-worker-2',
    count24h: 412,
    authorized: true,
    sensitiveData: false,
  },
];

export const demoServiceBindings: ServiceBinding[] = [
  {
    service: 'cms',
    displayName: '云监控 CMS',
    bound: true,
    resourceId: 'acs:cms:cn-hangzhou:1234:agf-agentteams',
    region: 'cn-hangzhou',
    health: 'healthy',
    note: 'AgentTeams 指标与告警已接入，采集间隔 60s。',
  },
  {
    service: 'apig',
    displayName: 'API 网关 APIG',
    bound: true,
    resourceId: 'apig-cn-hangzhou-agf-9f2c',
    region: 'cn-hangzhou',
    health: 'healthy',
    note: '模型与 MCP 出网流量经 APIG 转发至 AIGuardFabric 网关。',
  },
  {
    service: 'mse',
    displayName: '微服务引擎 MSE',
    bound: true,
    resourceId: 'mse-cn-hangzhou-agf-registry',
    region: 'cn-hangzhou',
    health: 'degraded',
    note: 'Nacos 注册中心同步延迟约 90s，AgentTeams 成员发现偶有滞后。',
  },
  {
    service: 'privatelink',
    displayName: '私网连接 Privatelink',
    bound: true,
    resourceId: 'pl-cn-hangzhou-agf-dw',
    region: 'cn-hangzhou',
    health: 'healthy',
    note: '数仓与向量库经 Privatelink 私网访问，不出公网。',
  },
  {
    service: 'schedulerx3',
    displayName: '分布式任务 SchedulerX3',
    bound: false,
    resourceId: null,
    region: 'cn-hangzhou',
    health: 'unknown',
    note: '未绑定：定时红队战役仍由本地 cron 触发，建议迁移以获得统一调度与重试。',
  },
];
