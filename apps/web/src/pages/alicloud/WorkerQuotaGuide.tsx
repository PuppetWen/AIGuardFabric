import { Alert, Space, Steps, Typography } from 'antd';
import { Link } from 'react-router-dom';

export default function WorkerQuotaGuide({ zh, assetId }: { zh: boolean; assetId?: string }) {
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Space direction="vertical" size={12} style={{ width: '100%' }}>
    <Steps direction="vertical" size="small" items={[
      { title: text('完成当前实例盘点', 'Complete inventory for the current instance'),
        description: text('在云连接与操作中配置 AgentTeams，执行完整团队盘点；在下方选择已经映射为平台资产的 Worker。',
          'Configure AgentTeams under Cloud connections and operations, run complete inventory, then select a Worker mapped to a platform asset.') },
      { title: text('创建 Worker 专属平台配额', 'Create a platform quota for this Worker'),
        description: <><Link to={assetId ? `/runtime?quota_target=${encodeURIComponent(assetId)}#quota-rules` : '/runtime#quota-rules'}>{text('打开运行时防护配额规则', 'Open quota rules in Runtime protection')}</Link>{text('：作用域 Agent，目标为该 Worker 资产 ID，维度 tokens，周期 day，超限 deny，正整数上限，并启用。',
          ': use scope agent, target this Worker asset ID, dimension tokens, window day, action deny, a positive limit, and enable the rule.')}</> },
      { title: text('绑定平台规则', 'Bind the platform rule'),
        description: text('选择 Worker 与匹配规则后保存绑定。保存或停用绑定只改变平台同步配置，不修改云端现有限制。',
          'Select the Worker and a matching rule, then save the binding. Saving or disabling a binding only changes platform synchronization settings; cloud limits remain as configured.') },
      { title: text('读取云端限制并检查差异', 'Read cloud limits and review the difference'),
        description: text('点击读取云端并确认读取操作；核对 Worker、平台上限、云 UsageLimit、LimitType 与 PeriodType。若云端未设置完整限额，先在厂商控制台配置正限额 token/day。预览有效期 5 分钟，版本变更或已使用的预览必须重新读取。',
          'Choose Read cloud and confirm the read. Review the Worker, platform limit, cloud UsageLimit, LimitType and PeriodType. If cloud limits are incomplete, first configure a positive token/day limit in the provider console. A preview expires after five minutes and must be reread after version changes or use.') },
      { title: text('显式确认写入并查看回读', 'Explicitly confirm the write and inspect readback'),
        description: text('检查差异并勾选确认后，才执行云端 UpdateWorker；服务器写入前再次读取，写入后 GetWorker 回读。检查最终状态和操作回执。',
          'Review the difference and check the confirmation before UpdateWorker runs. The server rereads before writing and calls GetWorker afterward. Inspect the final state and operation receipt.') },
    ]} />
    <Alert showIcon type="info" message={text('平台与云端用量独立', 'Platform and cloud usage are independent')}
      description={text('平台配额采用 UTC 自然日；云 UsedAmount、PeriodType 与 RuleStatus 按厂商返回单独展示，不能合并为共享计数桶。配置回读一致只证明限额配置，不证明云端权限或所有调用都经过平台。当前仅支持云 token/day；Mock 始终标记为模拟。',
        'Platform quotas use UTC calendar days. Cloud UsedAmount, PeriodType and RuleStatus are shown separately as returned by the provider, without a shared usage bucket. Matching readback verifies configuration, not cloud authorization or interception of every call. Only cloud token/day is supported; Mock is always labeled.')}/>
    <Typography.Paragraph><Link to="/settings?tab=apiKeys&createKey=1">{text('创建平台 API Key', 'Create a platform API key')}</Link>{text(' 时将资产绑定到同一 Worker，并使用该 Key 通过平台网关调用，实际平台消费才会归入该 Worker。云端配置同步本身不会接管厂商全部流量。',
      ' bound to the same Worker asset and use it through the platform gateway to attribute platform usage to this Worker. Cloud configuration synchronization does not intercept all provider traffic.')}</Typography.Paragraph>
    <Typography.Paragraph type="secondary">{text('写入成功回执不能替代最终回读一致。结果不确定、网络超时或写入失败时不要盲目重发：刷新查看持久操作回执，再重新读取云端状态并确认新的差异。409 表示版本或预览冲突，请刷新和重新读取。更换账号、实例、模式或 Worker 映射后重新绑定。任务重放暂不支持。',
      'A successful write receipt does not replace matching final readback. For uncertainty, timeout or write failure, refresh the durable receipt, read cloud state again and confirm a new difference before another write. A 409 means a version or preview conflict: refresh and reread. Rebind after account, instance, mode or Worker mapping changes. Task replay is not supported yet.')}</Typography.Paragraph>
    <Typography.Paragraph type="secondary">{text('观察到差异会生成关联 Worker 的 quota-drift 告警，有 alerts:read 权限时可直达告警详情。有效同步租约期间读取按钮不可用；租约到期后刷新回执，服务器允许时再手动读取，恢复过程不会自动写云。',
      'An observed difference creates a quota-drift alert linked to the Worker, with a detail link for alerts:read users. Read is unavailable during an active synchronization lease. After expiry, refresh the receipt and explicitly read when the server allows it; recovery does not automatically write to the cloud.')}</Typography.Paragraph>
  </Space>;
}
