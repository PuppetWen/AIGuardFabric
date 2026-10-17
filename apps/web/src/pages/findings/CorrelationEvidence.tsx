import { Collapse, Descriptions, Space, Steps, Typography } from 'antd';
import { useTranslation } from 'react-i18next';

export function CorrelationEvidence({ analysis }: { analysis: { rule: string; details: string } }) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  let details: Record<string, unknown> = {};
  try { details = JSON.parse(analysis.details) as Record<string, unknown>; } catch { /* Preserve older plain-text evidence below. */ }
  const labels: Record<string, string> = zh ? { observed: '观测值', mean: '历史均值', stddev: '标准差', samples: '学习样本数', z_score: 'Z 分数', kind: '偏离类型', hit_steps: '命中步骤数', total_steps: '总步骤数', span_secs: '事件跨度（秒）', window_secs: '规则窗口（秒）' }
    : { observed: 'Observed', mean: 'Historical mean', stddev: 'Standard deviation', samples: 'Training samples', z_score: 'Z score', kind: 'Deviation', hit_steps: 'Matched steps', total_steps: 'Total steps', span_secs: 'Event span (seconds)', window_secs: 'Rule window (seconds)' };
  const values = Object.entries(labels).filter(([key]) => details[key] !== undefined && details[key] !== null);
  const path = details.path as { entities?: unknown[] } | undefined;
  return <Space direction="vertical" style={{ width: '100%' }}>
    {values.length > 0 && <Descriptions size="small" column={2} bordered items={values.map(([key, label]) => ({ key, label, children: String(details[key]) }))} />}
    {Array.isArray(path?.entities) && <Steps direction="vertical" current={path.entities.length} items={path.entities.map(value => ({ title: String(value) }))} />}
    <Collapse items={[{ key: 'result', label: zh ? '完整分析结果' : 'Complete analysis result', children: <Typography.Paragraph copyable={{ text: analysis.details }}>
      <pre style={{ maxHeight: 350, overflow: 'auto', whiteSpace: 'pre-wrap' }}>{Object.keys(details).length ? JSON.stringify(details, null, 2) : analysis.details}</pre>
    </Typography.Paragraph> }, { key: 'rule', label: zh ? '触发时规则快照（可核对证据哈希）' : 'Rule snapshot at detection (for evidence hash verification)', children: <Typography.Paragraph copyable={{ text: analysis.rule }}>
      <pre style={{ maxHeight: 350, overflow: 'auto', whiteSpace: 'pre-wrap' }}>{analysis.rule}</pre>
    </Typography.Paragraph> }]} />
  </Space>;
}
