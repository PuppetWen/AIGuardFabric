import { Typography } from 'antd';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

export function EscalationGuide() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const steps = zh ? [
    '顶部铃铛显示真实送达的组织站内消息，按个人保存已读状态；点击消息查看正文和关联告警。标记消息已读不会确认告警，需要进入告警详情或列表处理。',
    '先在通知设置中配置、启用并测试渠道。个人用户可用站内消息；企业可配置钉钉、飞书、企微、SMTP 邮件、短信、Webhook、PagerDuty 或 Slack。接收人和地址来自通知设置，角色标签只用于展示，不会自动指派人员。',
    '按严重等级设置首次响应目标，最多添加三级升级。每级时间是超过响应目标后的分钟数，必须递增。例如响应目标 15 分钟、L1 逾期 5 分钟，即首见后 20 分钟触发。',
    '选择已启用且允许该严重等级的渠道，填写变更说明并保存。默认只对这次启用之后新产生的告警生效；勾选“纳入已有告警”会在启用时包含历史未响应告警。已有启用策略的范围保持不变。',
    '服务每 30 秒分批检查未确认告警，积压时会补齐已到期层级。每条告警每级只自动入队一次；修改或重新启用策略不会重发已完成层级。确认、解决、抑制告警或停用策略会停止尚未发送的升级通知。',
    '查看执行检查时间、错误、升级记录和通知状态。入队不代表送达；失败通知在 24 小时内最多自动尝试 8 次，仍失败时到通知设置检查渠道并手动重试。记录中的“已过保留期”代表投递详情已清理，不代表失败。',
    '版本冲突时保留草稿，先核对另一个管理员的修改再刷新。只有具备告警读写权限的个人账号可以发布；发布者失去权限会暂停自动升级，需要有权人员重新保存。模拟模式下外部渠道仅演练，站内消息仍实际保存。',
  ] : [
    'The top notification bell shows delivered organization messages and saves read status for each person. Open a message to read its body and linked alert. Marking a message read does not acknowledge the alert; handle it from the alert detail or list.',
    'Configure, enable and test channels in Notification settings first. Individuals can use the in-app inbox; teams can use DingTalk, Feishu, WeCom, SMTP email, SMS, Webhook, PagerDuty or Slack. Recipients come from channel settings. Role labels describe the escalation and do not assign people.',
    'Set a first-response target for each severity and add up to three tiers. Each delay is measured after that target and must increase. A 15-minute response target plus a 5-minute tier delay triggers 20 minutes after first seen.',
    'Select enabled channels whose minimum severity allows this route, enter a change reason and save. Newly enabled routes apply to new alerts by default. Include existing alerts explicitly to cover older unacknowledged alerts when enabling. Already enabled routes retain their scope.',
    'The server checks unacknowledged alerts in bounded batches every 30 seconds and catches up overdue tiers. Each alert/tier is automatically queued once, even after policy edits or re-enabling. Acknowledging, resolving or suppressing an alert, or disabling the policy, cancels unsent escalation messages.',
    'Check the last worker run, errors, escalation records and delivery status. Queued is not delivered. Failed sends get up to eight automatic attempts within 24 hours; inspect the channel and retry from Notification settings if needed. Expired details mean retention ended, not delivery failure.',
    'A version conflict preserves your draft. Review the other administrator’s changes before reloading. Publishing requires a personal account with alert read/write permissions; revoked publisher permissions pause escalation until an authorized person saves again. Mock mode simulates external sends; in-app messages are still stored.',
  ];
  return <><Typography.Paragraph><Link to="/settings?tab=notifications">{zh ? '打开通知设置与投递记录' : 'Open notification settings and delivery history'}</Link></Typography.Paragraph>
    <ol>{steps.map(step => <li key={step}><Typography.Paragraph>{step}</Typography.Paragraph></li>)}</ol></>;
}
