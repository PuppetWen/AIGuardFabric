import { useTranslation } from 'react-i18next';
import { Alert, Space, Steps, Table, Typography } from 'antd';
import { Link } from 'react-router-dom';

export function IntegrationGuide() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const rows = [
    { name: '飞书 / 钉钉 / 企业微信 / Slack', settings: text('填入群机器人 Webhook；按群安全设置填签名密钥。Slack 更新消息另需 bot_token、频道和原消息 ts。', 'Enter the robot webhook and any required signing secret. Slack updates also require bot_token, channel and the original message ts.') },
    { name: 'Email / SMTP', settings: text('主机、端口、加密方式、发件人、收件人；需登录时填写账号及 smtp_password。默认 587 / STARTTLS。', 'Host, port, transport encryption, sender and recipients. Add smtp_user and smtp_password when authentication is required. Defaults: 587 / STARTTLS.') },
    { name: 'Webhook', settings: text('填 webhook_url；需要鉴权时设置 auth_header_value。接收端检查返回状态和消息内容。', 'Set webhook_url and optionally auth_header_value. Check the response and message at the receiver.') },
    { name: 'Jira', settings: text('站点根地址、项目标识、工单类型；凭据填写 user_email 和 api_token。回写使用工单 Key；推进流程需要真实 transition_id。', 'Site root, project key, issue type, user_email and api_token. Push uses the issue key; workflow changes need a valid transition_id.') },
    { name: 'ServiceNow', settings: text('实例 HTTPS 地址、表名（默认 incident）和 api_token；回写使用 sys_id。', 'HTTPS instance URL, table (default incident) and api_token. Push uses sys_id.') },
    { name: '禅道 / ZenTao', settings: text('根地址、产品编号和 api_token；回写使用原缺陷单编号。', 'Root URL, product ID and api_token. Push uses the existing bug ID.') },
    { name: 'Syslog', settings: text('地址如 syslog://collector.example:514，选择 UDP / TCP。UDP 成功只表示已发送，需在接收端确认。', 'Use an address such as syslog://collector.example:514 and select UDP or TCP. UDP success only confirms local transmission; verify at the receiver.') },
    { name: 'EDR', settings: text('填写兼容平台 EDR 合约的网关地址和 api_token，先用 Mock。关闭 Mock 后，此页只允许读取，真实写操作须经案件审批。默认 dry_run=true；真实隔离须显式设 false。在资产详情绑定经过核对的主机编号，案件内选择该资产并审批。超时先核对远端任务。厂商 API 不同的设备需适配网关。', 'Set an EDR contract endpoint and api_token; start with Mock. After disabling Mock, this page is read-only and live writes require case approval. dry_run defaults to true and must be set false for actual isolation. Bind the verified host ID in asset details, then select that asset in a case and approve. Check the remote task after a timeout. Different vendor APIs need a gateway adapter.') },
    { name: 'SCIM / IAM', settings: text('填写身份平台 SCIM 2.0 基地址及 api_token，先用 Mock。确认平台支持 PATCH /Users/{id} 后，在凭据资产详情绑定远端用户 ID，并在案件中提交停用与审批。Live 集成页只展示回执，实际停用须经案件审批。SCIM 没有通用 dry-run；测试请用专门测试账号。', 'Set the SCIM 2.0 base URL and api_token; start with Mock. Confirm PATCH /Users/{id} support, bind the remote user ID to a credential asset, then submit and approve a case deactivation. The Live integration page shows receipts only. SCIM has no universal dry-run; use a dedicated test account.') },
  ];
  return <Space direction="vertical" size="middle" style={{ width: '100%' }}>
    <Typography.Title level={4}>{text('外部平台接入', 'Connect external platforms')}</Typography.Title>
    <Steps direction="vertical" items={[
      { title: text('选择租户与接入目标', 'Choose tenant and integration'), description: <Link to="/integrations">{text('打开集成管理，选择适配器', 'Open integrations and select an adapter')}</Link> },
      { title: text('先保存配置', 'Save configuration'), description: text('初次可开启模拟模式验证操作；真实模式需填完整设置。凭据加密保存，留空保留；修改地址后重新填凭据。', 'Start in mock mode to learn the workflow. Live mode requires complete settings. Secrets are encrypted; blank fields preserve them. Re-enter credentials after endpoint changes.') },
      { title: text('检查网络，再检查业务回执', 'Check connectivity, then a business receipt'), description: text('TCP 检查不会发消息，只验证端口可达。业务调用选发送、回写、读取或对账，填写目标和内容。模拟回执会明确标记 Mock。', 'TCP checks send no messages and verify only port reachability. Choose send, push, pull or sync and review its target and content. Mock receipts are explicitly labeled.') },
      { title: text('核对记录并处理异常', 'Review history and failures'), description: text('记录保留请求编号、配置版本和结果。超时或 started 未完成时先核对远端，避免重复建单或隔离。需要自动告警通知，在通知渠道设置中配置。', 'History records the request ID, configuration version and outcome. For timeouts or unfinished started records, check the remote system before retrying. Configure notification channels for automatic alerts.') },
    ]} />
    <Alert type="info" message={text('个人用户可先接一个 Webhook；企业用户先用测试群 / 测试工单项目验证，再切换正式目标。', 'Individuals can start with one webhook. Enterprises should validate a test channel or ticket project before switching to production.')} />
    <Table rowKey="name" size="small" pagination={false} dataSource={rows} columns={[
      { title: text('平台', 'Platform'), dataIndex: 'name', width: 180 },
      { title: text('填写与验证方式', 'Configuration and verification'), dataIndex: 'settings' },
    ]} />
  </Space>;
}
