import { memo, useMemo, useState } from 'react';
import { Alert, Button, Descriptions, Input, Pagination, Space, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useTranslation } from 'react-i18next';
import type { TraceGraph, TraceNode } from '@/types/agentTeamsTrace';

const pageSize = 50;
function TraceEvidenceGraph({ graph, total, truncated }: { graph: TraceGraph; total: number | null; truncated: boolean }) {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string>();
  const [edgePage, setEdgePage] = useState(1);
  const byId = useMemo(() => new Map(graph.nodes.map(node => [node.id, node])), [graph.nodes]);
  const filtered = useMemo(() => {
    const value = search.trim().toLowerCase();
    return graph.nodes.filter(node => [node.id, node.eventId, node.spanId, node.fromTeam, node.fromWorker,
      node.toTeam, node.toWorker, node.resolution].some(field => field?.toLowerCase().includes(value)));
  }, [graph.nodes, search]);
  const actualPage = Math.min(page, Math.max(1, Math.ceil(filtered.length / pageSize)));
  const visible = filtered.slice((actualPage - 1) * pageSize, actualPage * pageSize);
  const node = selected ? byId.get(selected) : undefined;
  const related = node ? graph.edges.filter(edge => edge.fromNodeId === node.id || edge.toNodeId === node.id) : [];
  const actualEdgePage = Math.min(edgePage, Math.max(1, Math.ceil(related.length / pageSize)));
  const visibleEdges = related.slice((actualEdgePage - 1) * pageSize, actualEdgePage * pageSize);
  const issues = node ? graph.issues.filter(issue => issue.nodeId === node.id) : [];
  const jump = (id: string) => {
    const index = graph.nodes.findIndex(item => item.id === id);
    if (index < 0) return;
    setSearch(''); setPage(Math.floor(index / pageSize) + 1); setSelected(id); setEdgePage(1);
  };
  const labels = { missing_span: text('缺少 Span', 'Missing span'), duplicate_span: text('重复 Span', 'Duplicate span'),
    missing_parent: text('缺少父记录', 'Missing parent'), ambiguous_parent: text('父 Span 不唯一', 'Ambiguous parent'),
    cycle: text('循环', 'Cycle'), conflicted_parent: text('父记录冲突', 'Conflicted parent') };
  const columns: ColumnsType<TraceNode> = [
    { title: text('平台记录 UUID', 'Audit record UUID'), width: 325, render: (_, item) => <Button type="link"
      style={{ padding: 0, whiteSpace: 'normal', height: 'auto', textAlign: 'left' }} onClick={() => { setSelected(item.id); setEdgePage(1); }}>{item.id}</Button> },
    { title: 'Span / Parent', width: 250, render: (_, item) => <Space direction="vertical" size={0}>
      <Typography.Text copyable={!!item.spanId}>{item.spanId ?? '—'}</Typography.Text>
      <Typography.Text type="secondary">{item.parentSpanId ?? '—'}</Typography.Text></Space> },
    { title: text('参与方 / 类型', 'Participants / kind'), width: 240, render: (_, item) => <Space direction="vertical" size={0}>
      <span>{item.fromTeam ?? '—'} / {item.fromWorker ?? '—'}</span><span>{item.toTeam ?? '—'} / {item.toWorker ?? '—'}</span>
      <span>{item.kind}</span></Space> },
    { title: text('证据状态', 'Evidence state'), width: 160, render: (_, item) => <Space direction="vertical" size={0}>
      <Tag color={item.resolution === 'conflict' ? 'red' : item.resolution === 'unknown' ? 'orange' : 'default'}>{item.resolution}</Tag>
      {item.mocked && <Tag color="blue">Mock</Tag>}</Space> },
  ];
  return <Space direction="vertical" size={10} style={{ width: '100%' }}>
    <Typography.Title level={5}>{text('观测关系证据', 'Observed relationship evidence')}</Typography.Title>
    <Typography.Text>{text(`本屏可见 ${visible.length} / 筛选 ${filtered.length} / 已返回 ${graph.nodes.length} 节点；窗口总事件 ${total ?? '未知'}。`,
      `Visible ${visible.length} / filtered ${filtered.length} / returned ${graph.nodes.length} nodes; window total events ${total ?? 'unknown'}.`)}</Typography.Text>
    <Alert type={graph.status === 'conflict' ? 'warning' : 'info'} showIcon message={text(`图状态 ${graph.status}；${graph.edges.length} 条已报告父边，${graph.issues.length} 个问题。只有 parent_span_id 证据形成边；每屏为关系局部列表，并非完整树。`,
      `Graph state ${graph.status}; ${graph.edges.length} reported parent edges, ${graph.issues.length} issues. Only parent_span_id evidence forms an edge. Each screen is a partial relationship list, not a complete tree.`)} />
    {truncated && <Alert type="warning" showIcon message={text('窗口事件超过2000节点上限。未返回的父记录或事件可能改变关系结论，请缩小时间窗。',
      'The window exceeds the 2000-node cap. Omitted parents/events may affect interpretation; narrow the window.')} />}
    <Input aria-label={text('筛选 Trace 节点', 'Filter Trace nodes')} placeholder={text('UUID / Span / Worker / Team / evidence', 'UUID / Span / Worker / Team / evidence')}
      value={search} onChange={event => { setSearch(event.target.value); setPage(1); }} style={{ maxWidth: 480 }} />
    <Table<TraceNode> rowKey="id" columns={columns} dataSource={visible} pagination={false} size="small" scroll={{ x: 1020 }} />
    <Pagination current={actualPage} pageSize={pageSize} total={filtered.length} showSizeChanger={false} onChange={setPage}
      aria-label={text('Trace 节点分页', 'Trace node pagination')} />
    {selected && !node && <Alert type="info" message={text('旧选择不在当前快照中，请重新选择记录。', 'The previous selection is absent from this snapshot. Select a current record.')} />}
    {node && <Space direction="vertical" role="region" aria-label={text('所选 Trace 节点证据', 'Selected Trace node evidence')} style={{ width: '100%' }}>
      <Descriptions bordered size="small" column={2} title={text('所选节点的实际证据', 'Actual evidence for selected node')} items={[
        { key: 'id', label: text('平台记录 UUID', 'Audit record UUID'), children: node.id },
        { key: 'event', label: 'Event ID', children: node.eventId },
        { key: 'span', label: 'Span ID', children: node.spanId ?? '—' },
        { key: 'parent', label: 'Parent span', children: node.parentSpanId ?? '—' },
        { key: 'time', label: text('事件时间', 'Event time'), children: node.eventTime },
        { key: 'task', label: 'Task ID', children: node.taskId ?? '—' },
        { key: 'source', label: 'Source / binding', children: `${node.sourceId} / ${node.bindingId}` },
        { key: 'auth', label: text('授权结论', 'Authorization'), children: text('未知；Mock 不证明授权', 'Unknown; Mock does not establish authorization') },
      ]} />
      <Space wrap>{issues.map((issue, index) => <Tag color={issue.status === 'conflict' ? 'red' : 'orange'} key={`${issue.kind}:${index}`}>{labels[issue.kind]}</Tag>)}</Space>
      {related.length === 0 && <Typography.Text type="secondary">{text('没有可验证的邻接父边；不根据任务名、团队或时间补边。', 'No verified adjacent parent edge; no edge is added from task name, team or time.')}</Typography.Text>}
      {related.length > 0 && <Typography.Text>{text(`本屏邻接父边 ${visibleEdges.length} / ${related.length}；其他节点和未观测边不在此列表中。`,
        `Visible adjacent parent edges ${visibleEdges.length} / ${related.length}; other nodes and unobserved edges are outside this list.`)}</Typography.Text>}
      {visibleEdges.map(edge => <Space key={`${edge.fromNodeId}:${edge.toNodeId}`} wrap>
        <Button type="link" onClick={() => jump(edge.fromNodeId)}>{edge.fromNodeId}</Button><span>→</span>
        <Button type="link" onClick={() => jump(edge.toNodeId)}>{edge.toNodeId}</Button>
        <Typography.Text type="secondary">parent_span_id = {edge.parentSpanId}</Typography.Text>
      </Space>)}
      {related.length > pageSize && <Pagination current={actualEdgePage} pageSize={pageSize} total={related.length}
        showSizeChanger={false} onChange={setEdgePage} aria-label={text('Trace 邻接边分页', 'Trace adjacent edge pagination')} />}
    </Space>}
  </Space>;
}
export default memo(TraceEvidenceGraph);
