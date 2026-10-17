import { useTranslation } from 'react-i18next';
import { Alert, List, Space, Table, Typography } from 'antd';
import { SchedulerGuide } from './SchedulerGuide';
import { TeamInventoryGuide } from './TeamInventoryGuide';
import TeamManagementGuide from './teamManagement/TeamManagementGuide';
import { RoleMappingGuide } from './agentteams-role-mapping/RoleMappingGuide';

export function CloudGuide() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const steps = zh ? [
    '在阿里云开通需要的服务，确认地域、实例/集群 ID 和 RAM 权限。个人用户可从单个服务的只读查询开始；企业用户可按业务账号分别配置。',
    '填写连接配置。使用 RAM 用户凭据，或选择 AssumeRole 并填写源凭据、目标角色 ARN、会话名称；预签发 STS 必须同时填写 Token 和真实到期时间。',
    '选择网络入口。官方 VPC 地址仅在可达的网络中使用；跨 VPC/账号需要另外配置 PrivateLink、路由和 DNS。自定义地址填服务根 URL，不附带接口路径或密钥。',
    '先启用模拟模式并保存，打开“操作与回执”熟悉参数和响应。服务端开启全局模拟时，关闭单个服务的模拟开关仍不会触达云端。',
    '具备真实环境后关闭模拟并保存，勾选确认，运行只读自检。成功只证明该查询接口可用，不能据此推断全部写权限、配额或私网连通性。',
    '按表格选择操作，填写必填项；嵌套对象与列表使用 JSON 编辑框。读取下一页时使用响应中的 NextToken 或增加页码。实际写入、删除前确认目标资源。',
    '检查实际回执和请求编号。失败按错误修正；结果不确定或请求中断时先核对云端，再准备新请求。相同请求编号不会再次发起业务调用。',
  ] : [
    'Enable the required Alibaba Cloud product and identify its region, instance/cluster IDs and RAM permissions. Start with a read-only query for one service.',
    'Configure a RAM user key, pre-issued STS token with its actual expiration, or AssumeRole with source credentials, role ARN and session name.',
    'Choose the network endpoint. VPC endpoints require reachable networking; cross-VPC/account access needs PrivateLink, routing and DNS. Custom endpoints are root URLs without paths or credentials.',
    'Save in mock mode and try Operations first. Server-wide mock mode overrides individual live settings.',
    'For real validation, disable mock, save and confirm a live read-only check. Success proves only that particular query; it does not establish all write permissions or quota headroom.',
    'Choose an operation and fill its parameters. Objects and arrays use JSON editors. For subsequent pages, use the returned NextToken or page number.',
    'Check receipts and request IDs. After a timeout or interruption, inspect cloud state before preparing a new request. Reusing a request ID does not repeat the operation.',
  ];
  const rows = [
    { service: 'CMS', entry: 'DescribeAlertHistoryList → PutCustomEvent / PutCustomMetric', note: text('指标需要应用分组 GroupId；告警回调通过日志源的 HTTP Push 接入。', 'Custom metrics require GroupId. Configure alarm callbacks using an HTTP Push log source.') },
    { service: 'APIG', entry: 'ListGateways / ListHttpApis / ListPlugins → CreatePluginAttachment', note: text('先获取网关、插件、环境或 API ID，再绑定插件；pluginConfig 按插件规范填写 Base64 编码的配置。访问日志从 SLS/Kafka/日志采集链路接入。', 'Obtain gateway, plugin, environment/API IDs before attaching plugins. Encode pluginConfig as required by the plugin. Ingest access logs through SLS/Kafka/log collectors.') },
    { service: 'MSE', entry: 'ListClusters → ListAnsServices / ListNacosConfigs → GetNacosConfig', note: text('先填写 MSE InstanceId；Nacos 列表不含完整配置内容，读取内容用 GetNacosConfig。创建与更新是不同操作。专用策略发布需单独绑定 Nacos engine origin，旧 OpenAPI endpoint 不能代替引擎地址；消费者加载仍需独立核查。', 'Set InstanceId first. Use GetNacosConfig for full content. Creating and updating configurations are separate operations. Dedicated policy publication requires a separate Nacos engine origin; the OpenAPI endpoint is not the engine address. Consumer loading needs independent verification.') },
    { service: 'PrivateLink', entry: 'ListVpcEndpoints → GetVpcEndpointAttribute / ListVpcEndpointSecurityGroups', note: text('查询状态与关联安全组；关联存在不等于端口可达，需在实际采集器网络验证 DNS 和 TCP。', 'Inspect endpoint status and attached security groups. Verify DNS and TCP from the collector network separately.') },
    { service: 'SchedulerX3', entry: 'ListJobs → CreateJob / UpdateJob → ListJobExecutions', note: text('填写 ClusterId 和 AppName；创建任务还需任务类型、时间类型及处理器/HTTP 目标。删除操作只作用于填写的 JobIds。', 'Set ClusterId and AppName, then job type, time type and handler/HTTP target. Delete only explicitly selected JobIds.') },
    { service: 'AgentTeams', entry: 'ListTeams / ListWorkers → GetTeam → /alicloud?tab=teams', note: text('填写 AgentTeams InstanceId 并完整盘点。团队维护提供已有用户选择、全量替换差异预览、明确确认和异步删除观察。', 'Set InstanceId and complete inventory. Team management provides existing-user selection, replacement previews, explicit confirmation and asynchronous deletion observation.') },
  ];
  return <Space direction="vertical" style={{ width: '100%' }} size="middle">
    <Typography.Title level={4}>{text('阿里云接入操作指南', 'Alibaba Cloud onboarding guide')}</Typography.Title>
    <Alert type="info" message={text('企业免密钥接入', 'Enterprise keyless access')}
      description={text('ECS 可选择实例 RAM Role，平台只使用 IMDSv2。Kubernetes 可选择 OIDC 工作负载身份，部署端挂载 ALIBABA_CLOUD_OIDC_TOKEN_FILE，并配置 OIDC Provider ARN 和目标角色。两者均须把当前租户 UUID 登记到 AGF_CLOUD_WORKLOAD_TENANTS；默认不允许租户共享主机身份。', 'ECS instance roles use IMDSv2. Kubernetes OIDC requires a mounted ALIBABA_CLOUD_OIDC_TOKEN_FILE, provider ARN and target role. Both require the tenant UUID in AGF_CLOUD_WORKLOAD_TENANTS; tenants cannot share host identity by default.')} />
    <List size="small" dataSource={steps} renderItem={(item, index) => <List.Item>{index + 1}. {item}</List.Item>} />
    <Table rowKey="service" size="small" pagination={false} dataSource={rows} columns={[
      { title: text('服务', 'Service'), dataIndex: 'service', width: 110 },
      { title: text('推荐操作顺序', 'Operation sequence'), dataIndex: 'entry', render: (entry: string, row: typeof rows[number]) => row.service === 'APIG'
        ? <Space direction="vertical" size={0}>{entry}<a href="/alicloud?tab=apig-policy">{text('已有独立 AiTokenRateLimit：打开专用阈值发布', 'Existing independent AiTokenRateLimit: open dedicated threshold publication')}</a>
          <Typography.Text type="secondary">{text('专用流程使用五 ID、普通 JSON config 与唯一 UpdatePolicy；不使用插件 Base64，也不承诺独占影响或消费者已加载。',
            'The dedicated workflow uses five IDs, ordinary JSON config and a unique UpdatePolicy; it uses no plugin Base64 and does not establish exclusive impact or consumer loading.')}</Typography.Text></Space>
        : row.service === 'MSE'
        ? <Space direction="vertical" size={0}>{entry}<a href="/alicloud?tab=mse-config">{text('打开 MSE 专用配置发布', 'Open MSE dedicated configuration publication')}</a></Space>
        : entry },
      { title: text('接入要点', 'Required setup'), dataIndex: 'note' },
    ]} />
    <Alert type="info" message={text('临时凭据与重试', 'Temporary credentials and retries')}
      description={text('AssumeRole 会话在到期前 5 分钟按需更新；源凭据必须仍有效。手动签发的 STS 到期后需更新。变更地址、账号、角色或凭据类型会清除旧凭据，避免发往错误目标。',
        'AssumeRole refreshes sessions on demand within five minutes of expiration; source credentials must remain valid. Update manually issued STS credentials when they expire. Changing endpoint, account, role or credential type clears old credentials.')} />
    <Typography.Paragraph>{text('接口和参数依据厂商公开 OpenAPI 定义；查看 ', 'Operations follow the provider OpenAPI definitions; see ')}
      <a href="https://api.aliyun.com/" target="_blank" rel="noreferrer">Alibaba Cloud OpenAPI Explorer</a>。
    </Typography.Paragraph>
    <TeamInventoryGuide />
    <a href="/alicloud?tab=teams">{text('打开团队维护', 'Open Team management')}</a>
    <TeamManagementGuide />
    <a href="/alicloud?tab=role-mapping">{text('打开 Role 权限映射', 'Open Role permission mapping')}</a>
    <RoleMappingGuide />
    <SchedulerGuide />
  </Space>;
}
