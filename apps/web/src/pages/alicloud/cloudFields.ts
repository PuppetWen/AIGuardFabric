import type { CloudConfig, CloudContract } from '@/api/cloud';
export const actionLabels: Record<string, string> = {
  PutCustomEvent: '上报自定义事件', PutCustomMetric: '上报自定义指标', DescribeAlertHistoryList: '读取报警历史',
  ListGateways: '查询网关', ListHttpApis: '查询 HTTP API', ListHttpApiRoutes: '查询 API 路由', ListPlugins: '查询已安装插件',
  ListPluginClasses: '查询插件类型', InstallPlugin: '安装插件', CreatePluginAttachment: '绑定插件', UpdatePluginAttachment: '更新插件绑定',
  ListPluginAttachments: '查询插件绑定', CreateAndAttachPolicy: '创建并绑定策略', UpdateAndAttachPolicy: '更新策略', ListPolicyClasses: '查询策略类型',
  ListClusters: '查询集群', ListAnsServices: '查询 Nacos 服务', ListNacosConfigs: '查询 Nacos 配置', GetNacosConfig: '读取配置内容',
  CreateNacosConfig: '创建 Nacos 配置', UpdateNacosConfig: '更新 Nacos 配置', ListGateway: '查询 MSE 网关',
  ListVpcEndpoints: '查询私网终端节点', GetVpcEndpointAttribute: '读取终端节点状态', ListVpcEndpointSecurityGroups: '查询已关联安全组', ListVpcEndpointZones: '查询节点可用区',
  ListJobs: '查询任务', CreateJob: '创建云任务', UpdateJob: '更新云任务', DeleteJobs: '删除所选云任务', ListJobExecutions: '查询执行记录', GetJobExecution: '读取执行详情',
  OperateEnableJobs: '启用所选任务', OperateDisableJobs: '停用所选任务', OperateExecuteJob: '立即执行云任务',
  ListTeams: '查询团队', GetTeam: '读取团队详情', CreateTeam: '创建团队', UpdateTeam: '更新团队', ListWorkers: '查询 Worker', GetWorker: '读取 Worker',
  UpdateWorker: '更新 Worker', ListTeamTasks: '查询团队任务', ListTeamDetails: '查询团队统计', GetModelInvocationSummary: '查询模型调用统计', GetTokenTrend: '查询 Token 趋势', ListMcps: '查询 MCP', ListModels: '查询模型',
};
const settingsFor: Record<string, string> = { InstanceId: 'instance_id', ClusterId: 'cluster_id', AppName: 'app_name', NamespaceId: 'namespace_id', RegionId: 'region_id', GroupId: 'group_id' };
export function initialParameters(operation: CloudContract | undefined, snapshot: CloudConfig): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  for (const parameter of operation?.parameters ?? []) {
    const key = parameter.name;
    const setting = snapshot.settings[settingsFor[key]];
    if (setting !== undefined) output[key] = setting;
    if (['MaxResults', 'PageSize', 'pageSize'].includes(key)) output[key] = 20;
    if (['Page', 'PageNum', 'pageNumber'].includes(key)) output[key] = 1;
    if (key === 'RegionId' && !output[key]) output[key] = 'cn-hangzhou';
  }
  if (operation?.action === 'PutCustomEvent') output.EventInfo = JSON.stringify([{ EventName: 'agf-security-event', Content: JSON.stringify({ description: 'Security event from AIGuardFabric' }), ...(snapshot.settings.group_id ? { GroupId: snapshot.settings.group_id } : {}) }], null, 2);
  if (operation?.action === 'PutCustomMetric') output.MetricList = JSON.stringify([{ Type: '0', MetricName: 'agf_blocked_requests', GroupId: snapshot.settings.group_id ?? '', Values: JSON.stringify({ value: 1 }), Dimensions: JSON.stringify({ source: 'aiguardfabric' }) }], null, 2);
  return output;
}
