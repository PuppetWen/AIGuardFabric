import { Alert, Collapse, Typography } from 'antd';
export default function CmsQueueGuide({ zh }: { zh: boolean }) {
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Collapse items={[{ key: 'guide', label: text('CMS 队列操作指南', 'CMS queue guide'), children: <>
    <Typography.Paragraph>{text('先在上方保存 CMS 连接：Mock 演示使用 cn-hangzhou、GroupId agf-cms-demo。将事件或指标明确入队，再选中条目并手动发送。入队不是云接受。',
      'Save the CMS connection above first. The Mock demo uses cn-hangzhou and GroupId agf-cms-demo. Explicitly enqueue an event or metric, select its row, then manually send. Enqueue does not mean cloud acceptance.')}</Typography.Paragraph>
    <Typography.Paragraph>{text('只有明确未发送或可信拒绝才能以新 UUID 发起新补传意图；每条最多五次。Accepted 永不重发。Unknown、响应丢失或审计未完成，请保留原 UUID 并读取原回执；本地恢复只结算已保存结果，不联系云。过期 started 且没有结果会永久记 Unknown。',
      'Only a confirmed not-sent or rejected item permits a new intent with a new UUID, at most five per item. Accepted is never resent. For Unknown, a lost response or pending audit, retain the original UUID and read its receipt. Local recovery settles retained facts without contacting CMS. An expired started attempt without evidence remains Unknown permanently.')}</Typography.Paragraph>
    <Typography.Paragraph>{text('归档释放正文，保留条目、请求和发送事实，不把 Unknown 变成可重发。源或凭据版本变化后旧条目仅可查看、本地结算或归档；新源需要新的明确入队意图。',
      'Archive frees payload content while retaining item, request and delivery facts. It never makes Unknown retryable. After source or credential revision changes, old items permit only reading, local settlement and archive. A new source requires a new explicit enqueue intent.')}</Typography.Paragraph>
    <Alert type="warning" showIcon message={text('CMS 没有该接口的幂等 ClientToken；无法保证外部效果恰好一次，也不证明消费者已处理。',
      'These CMS actions have no idempotency ClientToken. External effects are not exactly once and consumer processing remains unknown.')} />
    <Typography.Paragraph>{text('此队列只接收本页面的明确提交。通用云操作及 Scheduler 直接上报不自动入队。当前浏览器只能恢复同登录 User 的原请求；Key 发起的请求必须用原 Key 读取和恢复，管理员不能代替。Live 需要持久数据库、现有凭据和单独确认，Mock 不联网且内存离线模式只在同进程存活。',
      'This queue accepts explicit submissions from this page. Generic cloud operations and Scheduler direct reporting do not automatically enqueue. The console recovers requests from the same original User. Key requests require the original Key for reading and recovery; an administrator cannot substitute. Live requires a durable database, existing credentials and explicit confirmation. Mock makes no cloud calls, and memory offline mode survives only within its process.')}</Typography.Paragraph>
  </> }]} />;
}
