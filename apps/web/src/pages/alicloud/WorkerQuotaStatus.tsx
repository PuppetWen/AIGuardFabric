import { Alert, Descriptions, Space, Table, Tag, Typography } from 'antd';
import { Link } from 'react-router-dom';
import type { WorkerQuotaBinding, WorkerQuotaRule } from '@/types/agentTeamsQuotas';

interface Props {
  binding: WorkerQuotaBinding;
  rule?: WorkerQuotaRule;
  previewUsable: boolean;
  canReadAlerts: boolean;
  zh: boolean;
}

export default function WorkerQuotaStatus({ binding, rule, previewUsable, canReadAlerts, zh }: Props) {
  const text = (cn: string, en: string) => zh ? cn : en;
  const states = {
    unverified: text('未验证', 'Unverified'), 'in-sync': text('配置一致', 'Configuration matches'),
    drift: text('存在差异', 'Difference observed'), stale: text('绑定失效', 'Invalid binding'), disabled: text('已停用', 'Disabled'),
  };
  const operationStates = {
    started: text('执行中', 'In progress'), verified: text('回读已验证', 'Readback verified'),
    failed: text('失败', 'Failed'), uncertain: text('结果不确定', 'Result uncertain'), superseded: text('已被后续状态取代', 'Superseded'),
  };
  const observation = binding.observation;
  const operation = binding.lastOperation;
  const unknown = text('未知', 'Unknown');
  return <Space direction="vertical" size={12} style={{ width: '100%' }}>
    <Descriptions size="small" bordered column={2} items={[
      { key: 'state', label: text('绑定状态', 'Binding status'), children: <Space><Tag>{states[binding.state]}</Tag>{binding.mocked && <Tag color="blue">Mock</Tag>}</Space> },
      { key: 'versions', label: text('绑定 / 配额 / 云配置版本', 'Binding / quota / cloud version'), children: `${binding.version} / ${rule?.version ?? unknown} / ${binding.cloudVersion}` },
      { key: 'asset', label: text('Worker 资产 ID', 'Worker asset ID'), children: <Typography.Text copyable>{binding.assetId}</Typography.Text> },
      { key: 'scope', label: text('云实例范围 ID', 'Cloud instance scope ID'), children: <Typography.Text copyable>{binding.scopeId}</Typography.Text> },
      { key: 'desired', label: text('平台目标限额 · UTC 自然日', 'Platform target limit · UTC calendar day'), children: rule?.limit ?? unknown },
      { key: 'rule', label: text('绑定规则', 'Bound rule'), children: rule?.name ?? text('规则已移除', 'Rule removed') },
      { key: 'bound', label: text('绑定时间', 'Bound at'), children: binding.boundAt },
    ]} />
    {binding.busy && <Alert showIcon type="info" message={text('该 Worker 的同步操作仍持有有效租约；请等待并刷新回执，当前不能重新读取或写入。',
      'A synchronization operation still holds this Worker lease. Wait and refresh the receipt; another read or write is not available yet.')}
      description={binding.leaseExpiresAt ? `${text('租约截止时间', 'Lease expires at')}: ${binding.leaseExpiresAt}` : undefined} />}
    {binding.driftAlertId && <Alert type="warning" showIcon message={text('已生成配额漂移告警', 'A quota drift alert has been recorded')}
      description={canReadAlerts ? <Link to={`/alerts?alert=${encodeURIComponent(binding.driftAlertId)}`}>
        {text('查看配额漂移告警', 'View quota drift alert')}</Link>
        : <Typography.Text>{text('查看此告警需要 alerts:read 权限。', 'Viewing this alert requires alerts:read.')}</Typography.Text>} />}
    {observation ? <>
      <Space wrap><Typography.Text>{text('最近云端观察', 'Latest cloud observation')}: {observation.observedAt}</Typography.Text>
        {observation.mocked && <Tag color="blue">Mock</Tag>}<Tag color={previewUsable ? 'green' : 'default'}>{previewUsable ? text('可用于本次同步', 'Usable for this sync') : text('需重新读取后同步', 'Reread before syncing')}</Tag></Space>
      <Table rowKey="field" size="small" pagination={false} dataSource={[
        { field: 'UsageLimit', before: String(observation.usageLimit), after: String(rule?.limit ?? unknown) },
        { field: 'LimitType', before: observation.limitType, after: 'token' },
        { field: 'PeriodType', before: observation.periodType, after: 'day' },
      ]} columns={[
        { title: text('配置项', 'Setting'), dataIndex: 'field' },
        { title: text('已读取的云端配置', 'Observed cloud configuration'), dataIndex: 'before' },
        { title: text('平台目标配置', 'Platform target configuration'), dataIndex: 'after' },
      ]} />
      <Descriptions size="small" column={3} items={[
        { key: 'used', label: text('云端已用量 · 厂商周期', 'Cloud used amount · provider period'), children: observation.usedAmount ?? unknown },
        { key: 'ruleStatus', label: text('云端 RuleStatus', 'Cloud RuleStatus'), children: observation.ruleStatus ?? unknown },
        { key: 'over', label: text('云端是否超限', 'Cloud over limit'), children: observation.overLimit === null ? unknown : observation.overLimit ? text('是', 'Yes') : text('否', 'No') },
      ]} />
      {(observation.limitType !== 'token' || observation.periodType !== 'day') && <Alert type="info" showIcon
        message={text('当前云端维度或周期不支持同步；本期仅支持 token/day。', 'This cloud dimension or period cannot be synchronized. Only token/day is supported.')} />}
    </> : <Alert type="info" showIcon message={text('尚未读取云端配置，不能判断限额是否一致。', 'Cloud configuration has not been read; limit consistency is unverified.')} />}
    {binding.state === 'stale' && <Alert type="info" showIcon message={text('账号、实例、配置或配额身份已改变，请刷新盘点与规则后重新绑定。', 'Account, instance, configuration or quota identity changed. Refresh inventory and rules, then rebind.')} />}
    {binding.state === 'disabled' && <Alert type="info" showIcon message={text('同步绑定已停用，云端现有限制仍保留。', 'The synchronization binding is disabled. Existing cloud limits remain in place.')} />}
    {operation && <>
      <Descriptions size="small" bordered column={2} items={[
        { key: 'status', label: text('最近操作', 'Latest operation'), children: <Space><Tag>{operationStates[operation.status]}</Tag>{operation.mocked && <Tag color="blue">Mock</Tag>}</Space> },
        { key: 'receipt', label: text('操作回执 ID', 'Operation receipt ID'), children: <Typography.Text copyable>{operation.id}</Typography.Text> },
        { key: 'request', label: text('请求 ID', 'Request ID'), children: <Typography.Text copyable>{operation.requestId}</Typography.Text> },
        { key: 'changed', label: text('写入回执', 'Write receipt'), children: operation.changed
          ? text('已收到成功回执', 'Successful receipt received')
          : operation.status === 'verified' ? text('无需写入', 'No write needed') : text('未确认', 'Unconfirmed') },
        { key: 'start', label: text('开始时间', 'Started at'), children: operation.startedAt },
        { key: 'finish', label: text('结束时间', 'Finished at'), children: operation.finishedAt ?? text('尚未结束', 'Not finished') },
      ]} />
      {operation.error && <Alert type="error" showIcon message={operation.error} />}
      {operation.status === 'uncertain' && <Alert type="warning" showIcon
        message={text('云端写入结果不确定。不要直接重发，请重新读取云端状态并确认新的差异。', 'The cloud write result is uncertain. Read cloud state again and confirm a new difference before another write.')} />}
    </>}
  </Space>;
}
