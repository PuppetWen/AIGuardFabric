import { Alert, Space, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

export default function TraceGuide() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Space direction="vertical" size={8}>
    <Typography.Paragraph>{text('先完成云实例盘点、建立并绑定 APIWebhook 日志源。将项目 sdk/agentteams/python 或 sdk/agentteams/node 显式采集器接到自己的真实 Worker/Task/调用函数；先发 heartbeat 检查接收，再采集实际业务。Node 需要支持内置 SQLite 的 Node≥24，Python 依赖其标准库 SQLite。',
      'Complete cloud inventory, create and bind an APIWebhook source. Connect sdk/agentteams/python or sdk/agentteams/node explicitly to your actual Worker/Task/call functions. Start with a heartbeat, then observe real business. Node requires Node ≥24 with built-in SQLite; Python uses standard-library SQLite.')}</Typography.Paragraph>
    <Typography.Paragraph>{text('采集 Key 仅需 sources:write，为租户级权限，不是日志源专用 Key。模型网关 Key 单独使用 models:write 并绑定真实 Worker 资产；不要把业务 Key 放入采集请求。SDK 不修改业务网关、参数、返回值、异常或取消信号。',
      'The collector key needs only sources:write and is tenant-scoped, not source-specific. A separate model gateway key uses models:write and the actual Worker asset binding. Do not send the business key in telemetry. SDK instrumentation preserves business gateway, arguments, values, errors and cancellation.')}</Typography.Paragraph>
    <Space wrap><Link to="/settings?tab=apiKeys&createKey=1&scopes=sources%3Awrite">{text('创建采集 API Key', 'Create collector API key')}</Link>
      <Link to="/ingest">{text('日志源接入', 'Log source onboarding')}</Link></Space>
    <Typography.Paragraph>{text('从真实事件选择 Trace ID 或人工填写标识与 UTC 时间窗后点击查询。界面区分事件分页与关系分页：事件来自同一游标快照，关系覆盖该快照最多2000节点；每屏最多50个节点。点击记录 UUID 查看真正 parent_span_id 边和邻接节点，缺父、重复 Span、循环等保留为未知或冲突，不按 Task/Team/时间猜边。',
      'Select a Trace ID from an actual event or enter it with a UTC window, then query. Event pages share a cursor snapshot; relations cover at most 2000 nodes in that snapshot, with at most 50 visible per screen. Select a record UUID to inspect parent_span_id edges and neighbours. Missing parents, duplicate spans and cycles remain unknown/conflicted; no edge is inferred from Task/Team/time.')}</Typography.Paragraph>
    <Alert type="info" showIcon message={text('盘点不可用时数量未知；有效盘点下0只表示该窗口未观测。2000节点截断、缺日志或时钟偏差都可能留下缺口。Mock、正常函数返回、日志与 Trace 均不能证明调用授权。',
      'Unavailable inventory means an unknown count; zero under valid inventory means no observation in that window. Truncation, missing logs and clock skew leave gaps. Mock, normal function returns, logs and Trace do not establish call authorization.')} />
    <Typography.Paragraph>{text('游标有效期30分钟。返回第一页只显示同一查询保存的第一页和接收水位，不重新读取；其他页仍核对原游标快照。发生400/409时保留旧结果，核对标识/权限/盘点，再点击“刷新 Trace 查询”重新建立快照。SDK 响应丢失只重传相同事件 ID，不重做业务；本查询不写云、不恢复操作、不重放任务。',
      'Cursors expire after 30 minutes. Returning to page one restores the saved first page and receive watermark without GET; other pages still validate the original cursor snapshot. On 400/409 keep the old result, verify identity/permissions/inventory and use Refresh Trace query to start a new snapshot. SDK response loss retries the same event ID, never business. This query does not write to cloud, recover operations or replay tasks.')}</Typography.Paragraph>
  </Space>;
}
