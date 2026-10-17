import { Alert, Collapse, Typography } from 'antd';

export function CorrelationGuide({ zh }: { zh: boolean }) {
  return <Collapse items={[{ key: 'guide', label: zh ? '配置与接入步骤' : 'Configuration and onboarding', children: <>
    <ol>
      <li>{zh ? '在接入管理中连接日志源，先回放样本，确认类别、动作、主机、会话、用户和网络字段正确归一化。' : 'Connect a log source and replay a sample. Check normalized category, action, host, session, user and network fields.'}</li>
      <li>{zh ? '选择一个关联样例。优先按实体、来源或会话分组；跨来源图路径可选全部事件。示例默认停用。' : 'Choose an example. Prefer entity, source or session grouping; use all events for cross-source graph paths. Examples start disabled.'}</li>
      <li>{zh ? '填写名称、窗口和条件，并替换正负事件序列。序列最后一条作为本次触发事件；正样本必须命中，负样本必须不命中。' : 'Set the name, window and conditions, then adapt positive and negative event sequences. The last event is the trigger. Positive must match; negative must not.'}</li>
      <li>{zh ? '试跑通过后开启并保存。后续采集到的事件自动分析；到风险发现和告警中心查看事件证据。已有已完成事件不会因修改规则自动重跑。' : 'Validate, enable and save. Incoming events are analyzed automatically. Open Findings or Alerts for event evidence. Completed events are not automatically reprocessed after rule changes.'}</li>
      <li>{zh ? '配置通知渠道后，自动告警进入可靠通知队列。误报时先停用规则；历史版本可载入草稿，重新验证后发布。' : 'Configure notification channels to deliver automatic alerts through the durable queue. Disable noisy rules first. Load a historical version as a draft, validate and republish.'}</li>
    </ol>
    <Typography.Paragraph>{zh
      ? '时序：steps 中 categories/actions/rule_keys 为条件，min_events 为数量，optional 为可选步骤。图：from_kind/to_kind 与 max_hops 定义结构化实体共现路径；路径是调查线索，不能单独证明攻击。'
      : 'Temporal: steps use categories/actions/rule_keys, min_events and optional. Graph: from_kind/to_kind and max_hops describe paths through structured entity co-occurrence; paths are investigation evidence, not proof of an attack.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh
      ? '基线：支持上传/下载字节、输入/输出 Token 和费用微元。至少 5 个历史样本后检测偏离；缺失字段不当成零值，已判断异常的值不参与学习。历史从 SQL 窗口重建，重启后仍有效；启用 UTC 小时与星期分槽时，每个槽位需要分别积累样本。'
      : 'Baseline: supports inbound/outbound bytes, prompt/completion tokens and cost in micro-units. At least five prior samples are required. Missing fields are not zeros; detected anomalies are excluded from training. History is rebuilt from SQL after restart. UTC hour/weekday slots warm up separately.'}</Typography.Paragraph>
    <Alert type="info" showIcon message={zh ? '窗口与处理进度' : 'Window and processing status'} description={zh
      ? '窗口范围 1 秒至 7 天，每次最多读取 10000 条候选事件。超出时保留待处理状态，不截断后伪报成功；缩小来源/会话范围或时间窗口后自动重试。接入管理显示分析待处理与重试计数。离线内存模式可试跑，自动采集分析需要 SQL。'
      : 'Windows range from one second to seven days, with at most 10000 candidate events per evaluation. Over-limit work stays pending; narrow the source/session scope or window to retry. Ingestion shows pending/retry counts. Offline memory mode supports previews; automatic analysis requires SQL.'} />
  </> }]} />;
}
