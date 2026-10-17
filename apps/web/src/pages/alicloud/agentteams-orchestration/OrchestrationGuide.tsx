import { Space, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { useText } from './text';

export function OrchestrationGuide() {
  const t = useText();
  return <Space direction="vertical">
    <Typography.Paragraph>{t('1. 在阿里云连接设置中明确选择 AgentTeams 的 Mock 模式、region/instance，保存后点击完整盘点。这里 GET 不读云、不创建声明、不初始化接收端。真实云 DAG 拉取/写入尚无可信接口，Live 不支持此功能。',
      '1. In AliCloud connection settings, explicitly select AgentTeams Mock mode and a region/instance, save, then run complete inventory. GET here never reads the cloud, creates a declaration or initializes a receiver. There is no trusted cloud DAG read/write contract; this feature does not support Live.')} <Link to="/alicloud?tab=teams">AgentTeams</Link></Typography.Paragraph>
    <Typography.Paragraph>{t('2. 选择已盘点 Team，编辑或粘贴声明 JSON。schema_version=1；agent_ids 引用真实 Worker 名称，depends_on 引用节点 node_id；最多128节点/256KiB，不允许环、未知 Worker 或额外字段。manual/event/cron 只是声明，不执行任务。',
      '2. Choose an observed Team and edit or paste declaration JSON. Use schema_version=1, actual Worker names in agent_ids and node_id values in depends_on. Up to 128 nodes / 256 KiB; cycles, unknown Workers and extra fields are rejected. manual/event/cron are declarations and do not execute tasks.')} </Typography.Paragraph>
    <Typography.Paragraph>{t('3. 勾选应用所有声明确认，验证/预览后再明确提交保存。接收端初始未知；先保存，再选择 Push。Pull 只接受已知接收端；Both 冲突时本地优先。每次操作都预览并确认，绝不调用云厂商写接口。',
      '3. Confirm application ownership, validate/preview, then explicitly commit the local declaration. The receiver is initially unknown: save before Push. Pull requires a known receiver; Both prefers the local definition on conflict. Preview and confirm every action. No cloud vendor write API is called.')} </Typography.Paragraph>
    <Typography.Paragraph>{t('4. 409 后保留草稿和旧版本。GET 重读仅用于比较；明确采用后才更新基线，仍须手动预览/提交。超时或断线先用原 UUID 读取；404 不解锁重发。来源变化须新保存并确认清空旧 Mock 接收端，不能同步旧来源内容。',
      '4. A 409 keeps the draft and old revision. GET reload only compares; explicit adoption changes the baseline, followed by manual preview/commit. After a timeout or disconnect, read the original UUID; 404 never unlocks resubmission. A source change needs a new save and confirmation to clear the old Mock receiver; old-source content cannot sync.')} </Typography.Paragraph>
    <Typography.Paragraph>{t('5. 企业用数据库保留跨实例回执；个人单机无数据库仅在当前进程保留，重启不能保证。每租户64 Team、512永久请求；达到容量后拒绝新提交，不自动淘汰原事实。本地提交不证明消费者生效、任务执行、Role授权或云部署。',
      '5. Enterprises can use the database for receipts across instances. A personal installation without a database retains them only in the current process, with no restart guarantee. Limits are 64 Teams / 512 permanent requests per tenant; capacity rejects new commits without evicting original facts. A local commit does not prove consumer application, task execution, Role grants or cloud deployment.')} </Typography.Paragraph>
    <Typography.Paragraph>{t('接入现有应用：侧车模式通过 Agent 管理向导发现/审核现有配置并手动完成连接；SDK 模式显式安装并包裹调用，需要应用接入；网关模式在支持配置 Base URL/模型/Key 的客户端中改配置。不要把配置发现或遥测队列重试当成全部流量接管或业务重放。',
      'Connect existing applications: sidecar mode uses the Agent management wizard to discover/review existing configuration and finish the connection manually; SDK mode explicitly installs/wraps calls and requires application integration; gateway mode configures Base URL/model/Key in a client that supports it. Configuration discovery and telemetry retries are not proof of traffic interception or business replay.')} <Link to="/agents">{t('Agent 管理', 'Agent management')}</Link>{' · '}<Link to="/models">{t('模型网关', 'Model gateway')}</Link></Typography.Paragraph>
  </Space>;
}
