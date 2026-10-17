import { useState } from 'react';
import { Alert, Button, Collapse, Descriptions, Space, Tag, Timeline, Typography, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { callApi } from '@/api/transport';
import { useApiQuery } from '@/api/client';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import { useScopedOperation } from './useScopedOperation';
import { DataState } from './DataState';

interface Analysis {
  id: string; model: string; mocked: boolean; cached: boolean; snapshotSha256: string; usageRecordId: string;
  modelResponseUsed: boolean; contextBudgetTokens: number;
  promptTokens: number; completionTokens: number; costMicroCny: number;
  snapshot: { truncated: boolean; omittedFacts: number; omittedRecords: number;
    facts: { reference: string; kind: string; observedAt?: string | null; contentHash?: string | null; metadata: unknown }[] };
  assessment: { verdict: string; confidence: number; summary: string; evidenceRefs: string[];
    observations: { explanation: string; evidenceRefs: string[] }[];
    timeline: { evidenceRef: string; explanation: string }[];
    hypotheses: { fromRef: string; toRef: string; explanation: string }[] };
}

/** No demo fallback or request-supplied evidence; the backend loads the authenticated object's facts. */
export function SecurityAnalysisPanel(props: { resource: 'alerts' | 'cases'; id: string }) {
  const tenant = useAuthStore(state => state.tenant?.id);
  const generation = useAuthStore(state => state.sessionGeneration);
  return <AnalysisPanel key={`${props.resource}:${props.id}:${tenant}:${generation}`} {...props} />;
}

function AnalysisPanel({ resource, id }: { resource: 'alerts' | 'cases'; id: string }) {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const access = useSessionAccess();
  const operation = useScopedOperation();
  const [operationError, setOperationError] = useState<string>();
  const path = `/api/v1/${resource}/${encodeURIComponent(id)}/analysis`;
  const detail = useApiQuery('security-analysis', () => callApi<{ analysis: Analysis | null }>(path,
    () => null as never, { noFallback: true, opaqueKeys: ['metadata'] }), { key: [resource, id] });
  const analysis = detail.data?.data.analysis;
  const allowed = access.has(`${resource}:read`) && access.has(`${resource}:write`) && access.has('models:write');
  const analyze = () => operation.run(async current => {
    if (!allowed) return;
    setOperationError(undefined);
    try {
      await callApi(path, () => null as never, { noFallback: true, method: 'POST', body: {}, timeoutMs: 45_000 });
      if (current()) {
        await detail.refetch();
        if (current()) void message.success(zh ? '模型研判已保存' : 'Model review saved');
      }
    } catch (error) { if (current()) setOperationError(error instanceof Error ? error.message : String(error)); }
  });
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Space wrap><Typography.Title level={5} style={{ margin: 0 }}>{zh ? '模型证据研判' : 'Model evidence review'}</Typography.Title>
      <Button disabled={!allowed} loading={operation.busy} onClick={() => void analyze()}>{zh ? '研判当前证据' : 'Review stored evidence'}</Button></Space>
    <Typography.Text type="secondary">{zh ? '只读取当前组织的已保存证据。模型推测需人工复核，共现与时间先后不证明因果。' : 'Uses stored evidence in this organization. Review model hypotheses; co-occurrence and order do not prove causality.'}</Typography.Text>
    <Typography.Text type="secondary">{zh ? '模型只收到元数据；原始日志、提示词和载荷均未发送。此研判不能独立验证攻击内容。' : 'The model receives metadata only; raw logs, prompts and payloads are excluded. This review cannot independently validate attacks.'}</Typography.Text>
    {operationError && <Alert type="error" showIcon message={operationError} />}
    <DataState loading={detail.isLoading} error={detail.error} onRetry={() => void detail.refetch()}>
      {analysis ? <Space direction="vertical" style={{ width: '100%' }}>
        <Space wrap><Tag>{analysis.mocked ? (zh ? 'Mock 演示' : 'Mock demonstration') : (zh ? '实际模型调用' : 'Actual model call')}</Tag>
          {analysis.modelResponseUsed === false && <Tag color="warning">{zh ? '静态未知结论示例' : 'Derived unknown fixture'}</Tag>}
          <Tag>{analysis.model}</Tag><span>{analysis.assessment.verdict} · {Math.round(analysis.assessment.confidence * 100)}%</span></Space>
        {analysis.modelResponseUsed === false && <Typography.Text type="secondary">{zh
          ? 'Mock 输出未通过结构校验；下方是基于已保存引用生成的未知结论示例，用量仍来自实际 Mock 调用。'
          : 'The Mock output failed validation. This unknown fixture uses stored references; usage comes from the actual Mock call.'}</Typography.Text>}
        <Typography.Paragraph>{analysis.assessment.summary}</Typography.Paragraph>
        <Typography.Text type="secondary">{zh
          ? `模型输入：${analysis.snapshot.facts.length} 个证据项；省略 ${analysis.snapshot.omittedFacts ?? 0} 个证据项、${analysis.snapshot.omittedRecords ?? 0} 条记录。`
          : `Model input: ${analysis.snapshot.facts.length} evidence facts; ${analysis.snapshot.omittedFacts ?? 0} facts and ${analysis.snapshot.omittedRecords ?? 0} records omitted.`}</Typography.Text>
        {analysis.snapshot.truncated && <Typography.Text type="warning">{zh ? '输入为明确限量的证据子集，不能当作完整案件结论。' : 'Input is an explicitly bounded evidence subset, not a complete incident conclusion.'}</Typography.Text>}
        {analysis.assessment.observations.map((row, index) => <Typography.Paragraph key={index}>{row.explanation}<br /><Typography.Text code>{row.evidenceRefs.join(', ')}</Typography.Text></Typography.Paragraph>)}
        {analysis.assessment.timeline.length > 0 && <Timeline items={analysis.assessment.timeline.map(row => ({ children: <>
          <Typography.Text>{analysis.snapshot.facts.find(fact => fact.reference === row.evidenceRef)?.observedAt ?? '—'}</Typography.Text><br />{row.explanation}<br /><Typography.Text code>{row.evidenceRef}</Typography.Text>
        </> }))} />}
        {analysis.assessment.hypotheses.map((row, index) => <Typography.Paragraph key={index}><Tag color="warning">{zh ? '未证实假设' : 'Unverified hypothesis'}</Tag>{row.explanation}<br /><Typography.Text code>{row.fromRef} → {row.toRef}</Typography.Text></Typography.Paragraph>)}
        <Collapse items={[{ key: 'facts', label: zh ? '模型收到的证据快照' : 'Evidence snapshot supplied to the model', children:
          <Space direction="vertical" style={{ width: '100%' }}>{analysis.snapshot.facts.map(fact =>
            <Descriptions key={fact.reference} column={1} size="small" items={[
              { key: 'reference', label: zh ? '引用' : 'Reference', children: <Typography.Text code>{fact.reference}</Typography.Text> },
              { key: 'kind', label: zh ? '类型' : 'Kind', children: fact.kind },
              { key: 'at', label: zh ? '已保存时间' : 'Stored timestamp', children: fact.observedAt ?? '—' },
              { key: 'hash', label: zh ? '内容哈希' : 'Content hash', children: fact.contentHash ?? '—' },
              { key: 'metadata', label: zh ? '元数据' : 'Metadata', children: <Typography.Text style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(fact.metadata, null, 2)}</Typography.Text> },
            ]} />)}</Space>
        }, { key: 'provenance', label: zh ? '来源与实际用量' : 'Provenance and actual usage', children: <Descriptions column={1} size="small" items={[
          { key: 'refs', label: zh ? '证据引用' : 'Evidence references', children: analysis.assessment.evidenceRefs.join(', ') },
          { key: 'snapshot', label: 'Snapshot SHA', children: analysis.snapshotSha256 },
          { key: 'usage', label: 'Usage ID', children: analysis.usageRecordId },
          { key: 'context', label: zh ? '上下文预算（Token）' : 'Context budget (tokens)', children: analysis.contextBudgetTokens },
          { key: 'tokens', label: zh ? '实际输入 / 输出 Token' : 'Actual prompt / completion tokens', children: `${analysis.promptTokens} / ${analysis.completionTokens}` },
          { key: 'cost', label: zh ? '费用（微人民币）' : 'Cost (micro CNY)', children: analysis.costMicroCny },
        ]} /> }]} />
      </Space> : <Typography.Text type="secondary">{zh ? '尚未对当前对象保存模型研判。' : 'No saved model review for this object.'}</Typography.Text>}
    </DataState>
  </Space>;
}
